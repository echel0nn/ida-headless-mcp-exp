"""CAPA rule evaluation engine.

Evaluates 678 behavioral rules (derived from Mandiant CAPA, Apache-2.0)
against function index entries. No CAPA binary needed — pure evaluation
of API names and string references against precomputed rule conditions.

Rules cover 106 ATT&CK techniques across 17 categories:
anti-analysis, collection, communication, compiler, data-manipulation,
executable, exploitation, host-interaction, impact, lib, linking,
load-code, persistence, runtime, targeting.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

__all__ = ["capa_scan"]

_RULES: list[dict[str, Any]] | None = None
_RULES_PATH = Path(__file__).parent.parent.parent / "data" / "capa_rules.json.gz"


def _load_rules() -> list[dict[str, Any]]:
    """Load compressed CAPA rule database."""
    global _RULES  # noqa: PLW0603
    if _RULES is not None:
        return _RULES
    if not _RULES_PATH.exists():
        _RULES = []
        return _RULES
    with gzip.open(_RULES_PATH, "rt", encoding="utf-8") as f:
        _RULES = json.load(f)
    return _RULES


def capa_scan(
    function_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate CAPA rules against a binary's function index.

    For each function, checks if its callees and string references
    match any rule's API or string conditions.

    Args:
        function_entries: List of function index entries, each with
            'name', 'callees', 'string_refs' fields.

    Returns:
        Dict with matched capabilities, ATT&CK mappings, and per-function hits.
    """
    rules = _load_rules()
    if not rules:
        return {"capabilities": [], "total_rules": 0, "matches": 0}

    # Build binary-wide API and string sets for fast lookup
    all_apis: set[str] = set()
    all_strings: set[str] = set()
    per_func: dict[str, tuple[set[str], set[str]]] = {}

    for entry in function_entries:
        name = entry.get("name", "")
        callees = {c.lower() for c in entry.get("callees", [])}
        # Normalize: strip j_ prefix, A/W suffix
        normalized = set()
        for c in callees:
            n = c.lstrip("_").replace("j_", "")
            normalized.add(n)
            for suffix in ("a", "w", "exa", "exw"):
                if n.endswith(suffix) and len(n) > len(suffix):
                    normalized.add(n[:-len(suffix)])
        callees |= normalized
        strings = set(entry.get("string_refs", []))
        all_apis |= callees
        all_strings |= strings
        per_func[name] = (callees, strings)

    # Evaluate each rule
    capabilities: list[dict[str, Any]] = []
    attack_map: dict[str, list[str]] = {}

    for rule in rules:
        rule_apis = [a.lower() for a in rule.get("apis", [])]
        rule_strings = rule.get("strings", [])
        rule_substrings = rule.get("substrings", [])

        # Match: at least one API or string matches
        matched_apis = [a for a in rule_apis if a in all_apis]
        matched_strings = [s for s in rule_strings if s in all_strings]
        matched_subs = [
            s for s in rule_substrings
            if any(s.lower() in sr.lower() for sr in all_strings)
        ]

        if not matched_apis and not matched_strings and not matched_subs:
            continue

        # Find which functions triggered this rule
        triggering_functions: list[str] = []
        for func_name, (func_apis, func_strings) in per_func.items():
            func_hit = (
                any(a in func_apis for a in rule_apis)
                or any(s in func_strings for s in rule_strings)
                or any(
                    any(sub.lower() in sr.lower() for sr in func_strings)
                    for sub in rule_substrings
                )
            )
            if func_hit:
                triggering_functions.append(func_name)

        cap = {
            "rule": rule["name"],
            "namespace": rule.get("namespace", ""),
            "category": rule.get("category", ""),
            "matched_apis": matched_apis[:10],
            "matched_strings": (matched_strings + matched_subs)[:10],
            "functions": triggering_functions[:10],
            "function_count": len(triggering_functions),
        }

        att_ck = rule.get("att_ck", [])
        if att_ck:
            cap["att_ck"] = att_ck
            for technique in att_ck:
                attack_map.setdefault(technique, []).append(rule["name"])

        capabilities.append(cap)

    # Group by category
    by_category: dict[str, int] = {}
    for cap in capabilities:
        cat = cap["category"]
        by_category[cat] = by_category.get(cat, 0) + 1

    return {
        "total_rules_evaluated": len(rules),
        "matches": len(capabilities),
        "categories": dict(sorted(by_category.items(), key=lambda x: -x[1])),
        "att_ck_techniques": len(attack_map),
        "att_ck_coverage": sorted(attack_map.keys())[:30],
        "capabilities": capabilities,
    }
