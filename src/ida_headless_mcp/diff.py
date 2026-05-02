from __future__ import annotations

import difflib
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .function_index import FunctionIndexEntry

__all__ = [
    "FunctionDiffSummary",
    "FunctionPairMatch",
    "build_function_fingerprint",
    "compare_function_entries",
    "diff_binary_indexes",
    "diff_function_payloads",
]


@dataclass(frozen=True, slots=True)
class FunctionPairMatch:
    name_old: str
    name_new: str
    address_old: str
    address_new: str
    similarity: float
    old_size: int
    new_size: int
    old_complexity: int
    new_complexity: int
    added_callees: tuple[str, ...]
    removed_callees: tuple[str, ...]
    added_strings: tuple[str, ...]
    removed_strings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FunctionDiffSummary:
    functions_added: int
    functions_removed: int
    functions_changed: int
    functions_unchanged: int
    match_confidence_avg: float


def build_function_fingerprint(entry: FunctionIndexEntry) -> str:
    payload = {
        "size": entry.size_bytes,
        "complexity": entry.cyclomatic_complexity,
        "is_thunk": entry.is_thunk,
        "is_library": entry.is_library,
        "callees": list(entry.callees),
        "string_refs": list(entry.string_refs),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def compare_function_entries(old: FunctionIndexEntry, new: FunctionIndexEntry) -> FunctionPairMatch:
    added_callees = tuple(sorted(set(new.callees) - set(old.callees)))
    removed_callees = tuple(sorted(set(old.callees) - set(new.callees)))
    added_strings = tuple(sorted(set(new.string_refs) - set(old.string_refs)))
    removed_strings = tuple(sorted(set(old.string_refs) - set(new.string_refs)))

    score = 1.0
    size_den = max(old.size_bytes or 1, new.size_bytes or 1)
    complexity_den = max(old.cyclomatic_complexity or 1, new.cyclomatic_complexity or 1)
    score -= min(0.25, abs(new.size_bytes - old.size_bytes) / size_den)
    score -= min(
        0.20,
        abs(new.cyclomatic_complexity - old.cyclomatic_complexity) / complexity_den,
    )
    score -= min(0.25, (len(added_callees) + len(removed_callees)) * 0.05)
    score -= min(0.20, (len(added_strings) + len(removed_strings)) * 0.03)
    if old.is_library != new.is_library:
        score -= 0.05
    if old.is_thunk != new.is_thunk:
        score -= 0.05
    score = max(0.0, round(score, 4))

    return FunctionPairMatch(
        name_old=old.name,
        name_new=new.name,
        address_old=f"0x{old.address:x}",
        address_new=f"0x{new.address:x}",
        similarity=score,
        old_size=old.size_bytes,
        new_size=new.size_bytes,
        old_complexity=old.cyclomatic_complexity,
        new_complexity=new.cyclomatic_complexity,
        added_callees=added_callees,
        removed_callees=removed_callees,
        added_strings=added_strings,
        removed_strings=removed_strings,
    )


def diff_binary_indexes(old_entries: list[FunctionIndexEntry], new_entries: list[FunctionIndexEntry]) -> dict[str, Any]:
    old_by_name = {e.name: e for e in old_entries}
    new_by_name = {e.name: e for e in new_entries}

    old_names = set(old_by_name)
    new_names = set(new_by_name)

    added_names = sorted(new_names - old_names)
    removed_names = sorted(old_names - new_names)
    common_names = sorted(old_names & new_names)

    changed: list[FunctionPairMatch] = []
    unchanged = 0
    for name in common_names:
        old = old_by_name[name]
        new = new_by_name[name]
        if build_function_fingerprint(old) == build_function_fingerprint(new):
            unchanged += 1
            continue
        changed.append(compare_function_entries(old, new))

    summary = FunctionDiffSummary(
        functions_added=len(added_names),
        functions_removed=len(removed_names),
        functions_changed=len(changed),
        functions_unchanged=unchanged,
        match_confidence_avg=round(sum(c.similarity for c in changed) / len(changed), 4) if changed else 1.0,
    )

    return {
        "summary": {
            "functions_added": summary.functions_added,
            "functions_removed": summary.functions_removed,
            "functions_changed": summary.functions_changed,
            "functions_unchanged": summary.functions_unchanged,
            "match_confidence_avg": summary.match_confidence_avg,
        },
        "added": [
            {"name": e.name, "address": f"0x{e.address:x}", "size_bytes": e.size_bytes}
            for e in sorted((new_by_name[n] for n in added_names), key=lambda x: x.name)
        ],
        "removed": [
            {"name": e.name, "address": f"0x{e.address:x}", "size_bytes": e.size_bytes}
            for e in sorted((old_by_name[n] for n in removed_names), key=lambda x: x.name)
        ],
        "changed": [
            {
                "name_old": c.name_old,
                "name_new": c.name_new,
                "address_old": c.address_old,
                "address_new": c.address_new,
                "similarity": c.similarity,
                "size_delta": c.new_size - c.old_size,
                "complexity_delta": c.new_complexity - c.old_complexity,
                "callees_added": list(c.added_callees),
                "callees_removed": list(c.removed_callees),
                "strings_added": list(c.added_strings),
                "strings_removed": list(c.removed_strings),
            }
            for c in changed
        ],
    }


def diff_function_payloads(old_payload: dict[str, Any], new_payload: dict[str, Any]) -> dict[str, Any]:
    old_lines = str(old_payload.get("pseudocode", "")).splitlines()
    new_lines = str(new_payload.get("pseudocode", "")).splitlines()
    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=str(old_payload.get("name", old_payload.get("address", "old"))),
            tofile=str(new_payload.get("name", new_payload.get("address", "new"))),
            lineterm="",
        )
    )
    diff_unified = "\n".join(diff_lines)

    old_pseudo = "\n".join(old_lines)
    new_pseudo = "\n".join(new_lines)
    old_calls = _extract_call_names(old_pseudo)
    new_calls = _extract_call_names(new_pseudo)
    old_strings = _extract_quoted_strings(old_pseudo)
    new_strings = _extract_quoted_strings(new_pseudo)

    added_calls = sorted(set(new_calls) - set(old_calls))
    removed_calls = sorted(set(old_calls) - set(new_calls))
    added_strings = sorted(set(new_strings) - set(old_strings))
    removed_strings = sorted(set(old_strings) - set(new_strings))
    summary_signal = _summary_signal(diff_unified, added_calls, added_strings)

    return {
        "old": {
            "address": old_payload.get("address"),
            "name": old_payload.get("name"),
            "pseudocode": old_payload.get("pseudocode"),
            "size_bytes": old_payload.get("size_bytes"),
        },
        "new": {
            "address": new_payload.get("address"),
            "name": new_payload.get("name"),
            "pseudocode": new_payload.get("pseudocode"),
            "size_bytes": new_payload.get("size_bytes"),
        },
        "diff_unified": diff_unified,
        "added_calls": added_calls,
        "removed_calls": removed_calls,
        "added_strings": added_strings,
        "removed_strings": removed_strings,
        "summary_signal": summary_signal,
    }


def _extract_call_names(pseudocode: str) -> list[str]:
    out: list[str] = []
    token = []
    i = 0
    while i < len(pseudocode):
        ch = pseudocode[i]
        if ch.isalnum() or ch == '_':
            token.append(ch)
            i += 1
            continue
        if ch == '(' and token:
            name = ''.join(token)
            if name not in {"if", "for", "while", "switch", "return", "sizeof"}:
                out.append(name)
            token.clear()
            i += 1
            continue
        token.clear()
        i += 1
    return out


def _extract_quoted_strings(pseudocode: str) -> list[str]:
    out: list[str] = []
    in_quote = False
    cur: list[str] = []
    escape = False
    for ch in pseudocode:
        if not in_quote:
            if ch == '"':
                in_quote = True
                cur = []
            continue
        if escape:
            cur.append(ch)
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch == '"':
            out.append(''.join(cur))
            in_quote = False
            cur = []
            continue
        cur.append(ch)
    return out


def _summary_signal(diff_text: str, added_calls: list[str], added_strings: list[str]) -> str:
    diff_lower = diff_text.lower()
    added_text = " ".join(added_strings).lower()
    if any(name in added_calls for name in ("validate", "validate_length", "check_length", "bounds_check")):
        return "validation_added"
    if added_calls and any(term in diff_lower for term in ("\n+      if (", "\n+    if (", "\n+  if (")) and any(
        term in diff_lower for term in ("return -", "return (unsigned int)-", "else")
    ):
        return "validation_added"
    bounds_terms = ("if (", "if(", "maximum", "too large", "too long", "invalid length")
    if added_strings and any(term in diff_lower for term in bounds_terms):
        return "bounds_check_added"
    hardened_terms = ("too large", "too long", "invalid", "overflow", "out of bounds")
    if any(term in added_text for term in hardened_terms):
        return "error_path_hardened"
    if added_calls or added_strings:
        return "logic_rewritten"
    return "unknown"
