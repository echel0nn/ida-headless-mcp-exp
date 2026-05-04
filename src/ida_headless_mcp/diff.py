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
    "rank_security_relevance",
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


def diff_binary_indexes(
    old_entries: list[FunctionIndexEntry],
    new_entries: list[FunctionIndexEntry],
) -> dict[str, Any]:
    old_by_name = {e.name: e for e in old_entries}
    new_by_name = {e.name: e for e in new_entries}

    old_names = set(old_by_name)
    new_names = set(new_by_name)

    added_names = sorted(new_names - old_names)
    removed_names = sorted(old_names - new_names)
    common_names = sorted(old_names & new_names)

    # Phase 1: name-based matching on common names
    changed: list[FunctionPairMatch] = []
    unchanged = 0
    for name in common_names:
        old = old_by_name[name]
        new = new_by_name[name]
        if build_function_fingerprint(old) == build_function_fingerprint(new):
            unchanged += 1
            continue
        changed.append(compare_function_entries(old, new))

    # Phase 2: structure-hash matching for unmatched functions
    # Try to pair added/removed functions by structural similarity
    if added_names and removed_names:
        old_unmatched = {n: old_by_name[n] for n in removed_names}
        new_unmatched = {n: new_by_name[n] for n in added_names}
        # Build structure hashes (size_bucket, complexity, callee_count)
        for old_name, old_entry in list(old_unmatched.items()):
            best_score = 0.0
            best_new_name: str | None = None
            for new_name, new_entry in new_unmatched.items():
                score = _structure_similarity(old_entry, new_entry)
                if score > best_score and score >= 0.6:
                    best_score = score
                    best_new_name = new_name
            if best_new_name is not None:
                pair = compare_function_entries(
                    old_unmatched[old_name], new_unmatched[best_new_name]
                )
                changed.append(pair)
                del old_unmatched[old_name]
                del new_unmatched[best_new_name]
        # Update added/removed to reflect matched pairs
        added_names = sorted(new_unmatched.keys())
        removed_names = sorted(old_unmatched.keys())

    summary = FunctionDiffSummary(
        functions_added=len(added_names),
        functions_removed=len(removed_names),
        functions_changed=len(changed),
        functions_unchanged=unchanged,
        match_confidence_avg=(
            round(sum(c.similarity for c in changed) / len(changed), 4)
            if changed else 1.0
        ),
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
                "security_rank": rank_security_relevance(c),
            }
            for c in sorted(changed, key=lambda c: -rank_security_relevance(c))
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



def _structure_similarity(old: FunctionIndexEntry, new: FunctionIndexEntry) -> float:
    """Score structural similarity between two functions.

    Used for matching renamed/stripped functions by their shape.

    Args:
        old: Function entry from the old binary.
        new: Function entry from the new binary.

    Returns:
        A score in the range ``0.0`` to ``1.0`` where higher means more similar.
    """
    score = 1.0
    # Size similarity (within 50% = ok)
    size_ratio = min(old.size_bytes, new.size_bytes) / max(old.size_bytes or 1, new.size_bytes or 1)
    score *= (0.3 + 0.7 * size_ratio)
    # Complexity similarity
    cx_ratio = min(old.cyclomatic_complexity, new.cyclomatic_complexity) / max(
        old.cyclomatic_complexity or 1, new.cyclomatic_complexity or 1
    )
    score *= (0.3 + 0.7 * cx_ratio)
    # Callee overlap (Jaccard)
    old_callees = set(old.callees)
    new_callees = set(new.callees)
    if old_callees or new_callees:
        jaccard = len(old_callees & new_callees) / len(old_callees | new_callees)
        score *= (0.2 + 0.8 * jaccard)
    # Same library/thunk status
    if old.is_library != new.is_library:
        score *= 0.5
    if old.is_thunk != new.is_thunk:
        score *= 0.3
    return round(score, 4)


DANGEROUS_SINKS = {
    "memcpy", "memmove", "strcpy", "sprintf", "gets", "strcat",
    "malloc", "calloc", "realloc", "free",
    "system", "popen", "execve", "execl",
    "printf", "fprintf", "snprintf",
}


def rank_security_relevance(pair: FunctionPairMatch) -> float:
    """Score a changed function's security relevance.

    Higher scores mean the change is more likely to be a security fix.

    Args:
        pair: Matched old/new function pair to evaluate.

    Returns:
        A score from ``0.0`` (irrelevant) to ``10.0`` (critical).
    """
    score = 0.0
    # Bounds/validation callees added
    validation_names = {"validate", "check", "bounds", "verify", "sanitize"}
    for callee in pair.added_callees:
        callee_lower = callee.lower()
        if any(v in callee_lower for v in validation_names):
            score += 3.0
        if callee_lower in DANGEROUS_SINKS:
            score += 1.0  # new dangerous call is interesting
    # Dangerous callees removed (sanitized away)
    for callee in pair.removed_callees:
        if callee.lower() in DANGEROUS_SINKS:
            score += 2.0
    # Complexity increase (more branches = more validation)
    if pair.new_complexity > pair.old_complexity:
        score += min(2.0, (pair.new_complexity - pair.old_complexity) * 0.3)
    # Size increase (more code = likely added checks)
    if pair.new_size > pair.old_size:
        score += min(1.5, (pair.new_size - pair.old_size) / 50.0)
    # Error strings added
    error_terms = {"invalid", "overflow", "too large", "too long", "bounds", "error"}
    for s in pair.added_strings:
        if any(t in s.lower() for t in error_terms):
            score += 2.0
            break
    # Low similarity = major rewrite = likely security fix
    if pair.similarity < 0.7:
        score += 2.0
    elif pair.similarity < 0.85:
        score += 1.0
    return round(min(10.0, score), 2)
