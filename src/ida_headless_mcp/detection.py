"""Detection tools — cheap signals that inform consumer decisions.

These run on microcode and data sections without SMT solving.
They detect obfuscation, crypto primitives, and structural patterns
that the consumer uses to decide which expensive tools to invoke.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = ["detect_obfuscation", "detect_crypto_primitives"]

# Known crypto constants (first 8 bytes of each for matching)
# AES S-box first bytes: 0x63, 0x7C, 0x77, 0x7B
# SHA-256 K first values: 0x428A2F98, 0x71374491
# SHA-1 H: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
# MD5 T first: 0xD76AA478
# CRC32 polys: 0xEDB88320, 0x04C11DB7
_BASE64_ALPHA = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def detect_obfuscation(
    microcode_text: str,
    pseudocode: str,
    cfunc: Any = None,
) -> dict[str, Any]:
    """Detect obfuscation techniques using structural analysis.

    Args:
        microcode_text: Raw microcode from get_microcode.
        pseudocode: Decompiled pseudocode text.
        cfunc: Optional Hex-Rays cfunc_t for CTree analysis.

    Returns:
        Dict with obfuscation signals and confidence.
    """
    techniques: list[str] = []
    details: dict[str, Any] = {}

    # 1. MBA density — CTree expression depth if available, fallback to text
    if cfunc is not None:
        mba = _check_mba_ctree(cfunc)
    else:
        mba = _check_mba_density(microcode_text)
    details["mba_density"] = mba["density"]
    if mba["detected"]:
        techniques.append("mba_substitution")
        details["mba_expressions"] = mba.get("examples", [])[:3]

    # 2. CFF — look for dispatcher in pseudocode structure
    cff = _check_cff(pseudocode)
    details["cff_detected"] = cff["detected"]
    if cff["detected"]:
        techniques.append("control_flow_flattening")
        details["dispatcher_variable"] = cff.get("state_var")
        details["switch_cases"] = cff.get("case_count", 0)

    # 3. Expression depth via CTree (structural, not parenthesis counting)
    if cfunc is not None:
        depth = _check_expression_depth_ctree(cfunc)
    else:
        depth = _check_expression_depth(pseudocode)
    details["max_expression_depth"] = depth["max_depth"]
    details["deep_expressions"] = depth["count"]
    if depth["count"] > 3:
        techniques.append("instruction_substitution")

    obfuscated = len(techniques) > 0
    if len(techniques) >= 3:
        confidence = "high"
    elif len(techniques) >= 1:
        confidence = "medium"
    else:
        confidence = "none"

    return {
        "obfuscated": obfuscated,
        "techniques": techniques,
        "confidence": confidence,
        **details,
    }


def detect_crypto_primitives(
    data_bytes: list[tuple[int, bytes]],
    function_entries: list[dict[str, Any]],
    string_refs: list[str],
) -> dict[str, Any]:
    """Detect known cryptographic primitives in data and code.

    Args:
        data_bytes: List of (address, bytes) from data sections.
        function_entries: Function index entries with callees/size.
        string_refs: All string references in the binary.

    Returns:
        Dict with detected primitives and their locations.
    """
    primitives: list[dict[str, Any]] = []

    # Load signature database
    import json as _json
    from pathlib import Path as _Path
    sig_path = _Path(__file__).parent.parent.parent / "data" / "crypto_sigs.json"
    sigs: list[dict] = []
    if sig_path.exists():
        sigs = _json.loads(sig_path.read_text(encoding="utf-8"))

    # Scan data sections against all signatures
    for addr, data in data_bytes:
        for sig in sigs:
            hex_str = sig["bytes"].replace(" ", "")[:32]
            if len(hex_str) % 2 != 0:
                hex_str = hex_str[:-1]  # ensure even length
            try:
                pattern = bytes.fromhex(hex_str)
            except ValueError:
                continue  # skip malformed signature
            idx = data.find(pattern)
            if idx >= 0:
                primitives.append({
                    "type": sig["name"],
                    "algorithm": sig["algo"],
                    "address": f"0x{addr + idx:x}",
                    "confidence": "high",
                })
                break  # one match per data section per signature

        # Fallback: AES S-box (most common, ensure it's always checked)
        if not any(p.get("type") == "AES_S_box" for p in primitives):
            idx = data.find(bytes([0x63, 0x7C, 0x77, 0x7B]))
            if idx >= 0 and len(data) >= idx + 256:
                primitives.append({
                    "type": "AES_S_box",
                    "algorithm": "AES",
                    "address": f"0x{addr + idx:x}",
                    "confidence": "high",
                })

        # SHA-256 K constants
        for i in range(len(data) - 16):
            val = int.from_bytes(data[i:i + 4], "little")
            if val == 0x428A2F98:
                val2 = int.from_bytes(data[i + 4:i + 8], "little")
                if val2 == 0x71374491:
                    primitives.append({
                        "type": "sha256_constants",
                        "address": f"0x{addr + i:x}",
                        "confidence": "high",
                    })
                    break

        # SHA-1 init values
        for i in range(len(data) - 20):
            val = int.from_bytes(data[i:i + 4], "big")
            if val == 0x67452301:
                val2 = int.from_bytes(data[i + 4:i + 8], "big")
                if val2 == 0xEFCDAB89:
                    primitives.append({
                        "type": "sha1_constants",
                        "address": f"0x{addr + i:x}",
                        "confidence": "high",
                    })
                    break

        # CRC32 polynomial
        for i in range(len(data) - 4):
            val = int.from_bytes(data[i:i + 4], "little")
            if val in (0xEDB88320, 0x04C11DB7):
                primitives.append({
                    "type": "crc32_polynomial",
                    "address": f"0x{addr + i:x}",
                    "confidence": "medium",
                })
                break

        # Base64 alphabet
        idx = data.find(_BASE64_ALPHA)
        if idx >= 0:
            primitives.append({
                "type": "base64_alphabet",
                "address": f"0x{addr + idx:x}",
                "confidence": "high",
            })

    # String-based detection
    crypto_strings = [
        s for s in string_refs
        if any(k in s.lower() for k in (
            "aes", "sha", "md5", "rsa", "rc4", "des", "blowfish",
            "chacha", "salsa", "hmac", "pbkdf", "bcrypt", "argon",
        ))
    ]
    if crypto_strings:
        primitives.append({
            "type": "crypto_strings",
            "strings": crypto_strings[:10],
            "confidence": "medium",
        })

    return {
        "primitives_found": len(primitives),
        "primitives": primitives,
    }


# ---- Internal helpers ----


def _check_mba_density(microcode: str) -> dict[str, Any]:
    """Check ratio of boolean+arithmetic mixed operations."""
    bool_ops = len(re.findall(r'\b(xor|and|or|not)\b', microcode, re.I))
    arith_ops = len(re.findall(r'\b(add|sub|mul|neg)\b', microcode, re.I))
    total = bool_ops + arith_ops
    if total == 0:
        return {"detected": False, "density": 0.0, "examples": []}

    density = bool_ops / total if total > 0 else 0.0

    # MBA = bool ops mixed WITH arith ops in same expressions
    # High density of both = likely MBA
    examples: list[str] = []
    for line in microcode.splitlines():
        has_bool = bool(re.search(r'\b(xor|and|or)\b', line, re.I))
        has_arith = bool(re.search(r'\b(add|sub|mul)\b', line, re.I))
        if has_bool and has_arith:
            examples.append(line.strip()[:80])

    return {
        "detected": len(examples) >= 3 and density > 0.3,
        "density": round(density, 3),
        "examples": examples,
    }


def _check_cff(pseudocode: str) -> dict[str, Any]:
    """Check for control flow flattening dispatcher pattern."""
    # Look for while(1) { switch(var) { ... } } pattern
    switch_match = re.search(
        r'while\s*\(\s*1\s*\)\s*\{[^}]*switch\s*\(\s*(\w+)\s*\)',
        pseudocode, re.S,
    )
    if switch_match:
        state_var = switch_match.group(1)
        case_count = len(re.findall(r'\bcase\b', pseudocode))
        return {
            "detected": case_count > 4,
            "state_var": state_var,
            "case_count": case_count,
        }

    # Alternative: do { ... } while pattern
    do_switch = re.search(
        r'do\s*\{[^}]*switch\s*\(\s*(\w+)\s*\)',
        pseudocode, re.S,
    )
    if do_switch:
        state_var = do_switch.group(1)
        case_count = len(re.findall(r'\bcase\b', pseudocode))
        return {
            "detected": case_count > 4,
            "state_var": state_var,
            "case_count": case_count,
        }

    return {"detected": False}


def _check_opaque_predicates(pseudocode: str) -> dict[str, Any]:
    """Check for likely opaque predicate patterns."""
    patterns = [
        r'if\s*\(\s*\w+\s*\*\s*\w+\s*%\s*2\s*==\s*0\s*\)',  # x*x % 2 == 0
        r'if\s*\(\s*\(\s*\w+\s*\|\s*1\s*\)\s*!=\s*0\s*\)',   # (x|1) != 0
        r'if\s*\(\s*\w+\s*\*\s*\(\s*\w+\s*\+\s*1\s*\)\s*%\s*2',  # x*(x+1) % 2
        r'if\s*\(\s*\w+\s*\^\s*\w+\s*\|\s*\w+\s*&\s*\w+\s*\)',   # complex MBA in condition
    ]
    examples: list[str] = []
    for pat in patterns:
        for m in re.finditer(pat, pseudocode):
            examples.append(m.group()[:60])

    return {"count": len(examples), "examples": examples}


def _check_expression_depth(pseudocode: str) -> dict[str, Any]:
    """Check for abnormally deep expressions (substitution obfuscation)."""
    max_depth = 0
    deep_count = 0
    for line in pseudocode.splitlines():
        depth = line.count('(')
        if depth > max_depth:
            max_depth = depth
        if depth > 5:
            deep_count += 1

    return {"max_depth": max_depth, "count": deep_count}


def _check_dead_code(microcode: str) -> dict[str, Any]:
    """Check for dead assignments in microcode."""
    # Look for assignments whose LHS never appears again
    assigns = re.findall(r'(\w+)\s*=\s', microcode)
    dead_count = 0
    for var in assigns:
        # Count occurrences (rough heuristic)
        count = microcode.count(var)
        if count <= 1:  # only the assignment itself
            dead_count += 1

    return {"count": dead_count}



def _check_mba_ctree(cfunc: Any) -> dict[str, Any]:
    """Check MBA density via CTree expression tree structure."""
    import ida_hexrays

    bool_ops = {
        ida_hexrays.cot_band, ida_hexrays.cot_bor,
        ida_hexrays.cot_xor, ida_hexrays.cot_bnot,
    }
    arith_ops = {
        ida_hexrays.cot_add, ida_hexrays.cot_sub,
        ida_hexrays.cot_mul, ida_hexrays.cot_neg,
    }

    # Count expressions that mix bool + arith in the same assignment RHS
    mixed_count = 0
    total_assigns = 0
    examples: list[str] = []

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            nonlocal mixed_count, total_assigns
            if expr.op == ida_hexrays.cot_asg:
                total_assigns += 1
                ops_found: set[str] = set()
                _collect_ops(expr.y, bool_ops, arith_ops, ops_found)
                if "bool" in ops_found and "arith" in ops_found:
                    mixed_count += 1
                    if len(examples) < 5:
                        examples.append(f"0x{expr.ea:x}")
            return 0

    Visitor().apply_to_exprs(cfunc.body, None)

    density = mixed_count / max(total_assigns, 1)
    return {
        "detected": mixed_count >= 3 and density > 0.2,
        "density": round(density, 3),
        "mixed_expressions": mixed_count,
        "examples": examples,
    }


def _collect_ops(expr: Any, bool_ops: set, arith_ops: set, result: set) -> None:
    """Recursively collect op categories in an expression tree."""
    if expr is None:
        return
    if expr.op in bool_ops:
        result.add("bool")
    if expr.op in arith_ops:
        result.add("arith")
    if hasattr(expr, 'x') and expr.x:
        _collect_ops(expr.x, bool_ops, arith_ops, result)
    if hasattr(expr, 'y') and expr.y:
        _collect_ops(expr.y, bool_ops, arith_ops, result)


def _check_expression_depth_ctree(cfunc: Any) -> dict[str, Any]:
    """Check expression tree depth via CTree (structural, not text)."""
    import ida_hexrays

    max_depth = 0
    deep_count = 0

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            nonlocal max_depth, deep_count
            if expr.op == ida_hexrays.cot_asg:
                d = _expr_depth(expr.y)
                if d > max_depth:
                    max_depth = d
                if d > 6:  # threshold for 'abnormally deep'
                    deep_count += 1
            return 0

    Visitor().apply_to_exprs(cfunc.body, None)
    return {"max_depth": max_depth, "count": deep_count}


def _expr_depth(expr: Any) -> int:
    """Compute depth of an expression tree."""
    if expr is None:
        return 0
    left = _expr_depth(getattr(expr, 'x', None)) if hasattr(expr, 'x') else 0
    right = _expr_depth(getattr(expr, 'y', None)) if hasattr(expr, 'y') else 0
    return 1 + max(left, right)
