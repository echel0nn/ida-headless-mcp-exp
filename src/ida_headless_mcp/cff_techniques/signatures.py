"""Known obfuscator fingerprints for control-flow flattening.

Each signature describes the combination of dispatcher pattern, opaque
predicate family, state-variable shape, and per-family characteristics
that a known protector emits. The signature database is small and
intentionally hand-curated: every entry is grounded in published
analyses or compiler source. Adding a new entry should be a documented
event, not a heuristic guess.

Matching is fuzzy by design. A detection that misses a feature (for
example, opaque predicates that the simplifier could not classify)
should still match the right family if the dispatcher and state shape
agree. Variants that resemble nothing in the database return ``None``
rather than forcing a match against the weakest scorer.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._types import CffSignature

if TYPE_CHECKING:
    from ._types import CffDetectionResult

__all__ = ["load_signatures", "match_signature"]


# Minimum total score for a confident match.
#
# Score breakdown is documented on ``match_signature``:
#   dispatcher overlap   = 0.30
#   opaque overlap       = 0.30
#   state-variable shape = 0.20
#   characteristic bonus = up to 0.20
#
# A bare dispatcher hit (0.30) is too weak to name a family -- many
# protectors share dispatcher topology. Dispatcher + state-variable
# shape (0.50) is the floor for naming. Anything below that returns
# ``(None, 0.0)`` as an unknown variant.
_MATCH_THRESHOLD: float = 0.5


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------


def load_signatures() -> list[CffSignature]:
    """Return all known CFF obfuscator signatures.

    Returns:
        List of every shipped ``CffSignature`` in priority-neutral order.
        Callers must not depend on the order; ``match_signature`` scores
        each entry independently.
    """
    return [
        CffSignature(
            name="ollvm_vanilla",
            family="OLLVM",
            dispatcher_patterns=["sub_jz_chain", "cmp_je_table"],
            opaque_patterns=["quadratic"],
            state_var_types=["stack_fixed", "stack_any"],
            characteristics={
                "state_values_random_32bit": True,
                "one_dispatcher_per_function": True,
                "handlers_return_to_dispatcher": True,
                "default_opaque_formula": "x*(x+1)%2==0",
            },
        ),
        CffSignature(
            name="hikari",
            family="OLLVM",
            dispatcher_patterns=["sub_jz_chain", "cmp_je_table"],
            opaque_patterns=["quadratic", "mba"],
            state_var_types=["stack_fixed", "stack_any"],
            characteristics={
                "string_encryption": True,
                "indirect_branch_obfuscation": True,
                "anti_class_dump": True,
            },
        ),
        CffSignature(
            name="lcg_stack_cff",
            family="LCG-CFF",
            dispatcher_patterns=["sub_jz_chain"],
            opaque_patterns=["lcg"],
            state_var_types=["stack_fixed"],
            characteristics={
                "per_function_lcg_multiplier": True,
            },
        ),
        CffSignature(
            name="tigress",
            family="Tigress",
            dispatcher_patterns=["switch_jump_table", "indirect_computed"],
            opaque_patterns=["mba", "constant_fold"],
            state_var_types=["stack_any", "register"],
            characteristics={
                "virtualization_hybrid": True,
                "handler_splitting": True,
                "mba_expressions": True,
            },
        ),
        CffSignature(
            name="themida_cff",
            family="Themida",
            dispatcher_patterns=["cmp_je_table", "indirect_computed"],
            opaque_patterns=["constant_fold"],
            state_var_types=["stack_any", "global"],
            characteristics={
                "encrypted_state": True,
                "dynamic_dispatcher": True,
                "anti_dump": True,
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Detection-result accessors
# ---------------------------------------------------------------------------
#
# ``CffDetectionResult`` is owned by the sibling ``_types`` module. We
# read its fields defensively so that minor naming drift (singular vs
# plural, list vs dict-of-name) does not silently zero out scores.


def _detected_dispatchers(detection: Any) -> set[str]:
    """Extract detected dispatcher pattern names as a set of strings."""
    raw = getattr(detection, "dispatcher_patterns", None)
    if raw is None:
        raw = getattr(detection, "dispatchers", None)
    return _coerce_name_iterable(raw)


def _detected_opaques(detection: Any) -> set[str]:
    """Extract detected opaque-predicate pattern names as a set of strings.

    Tolerates either ``list[str]`` (just names) or ``list[dict]`` where
    each dict has a ``pattern`` or ``name`` key -- the latter is the
    shape the design notes use when carrying per-instance metadata.
    """
    raw = getattr(detection, "opaque_patterns", None)
    if raw is None:
        raw = getattr(detection, "opaques", None)
    return _coerce_name_iterable(raw)


def _detected_state_vars(detection: Any) -> set[str]:
    """Extract detected state-variable type names as a set of strings.

    Accepts a single string (``state_var_type``), a list of strings
    (``state_var_types``), or either rolled into a dict with ``type``.
    """
    sv = getattr(detection, "state_var_type", None)
    if isinstance(sv, str):
        return {sv}
    if isinstance(sv, dict):
        t = sv.get("type")
        if isinstance(t, str):
            return {t}
    if isinstance(sv, list):
        return _coerce_name_iterable(sv)
    svs = getattr(detection, "state_var_types", None)
    if isinstance(svs, list):
        return _coerce_name_iterable(svs)
    if isinstance(svs, str):
        return {svs}
    return set()


def _detected_characteristics(detection: Any) -> dict[str, Any]:
    """Extract the detection's characteristics dict, or empty if absent."""
    c = getattr(detection, "characteristics", None)
    if isinstance(c, dict):
        return c
    return {}


def _coerce_name_iterable(raw: Any) -> set[str]:
    """Coerce a list of names-or-dicts into a set of plain string names.

    Args:
        raw: List of strings, list of dicts (with ``pattern`` or
            ``name``), or ``None``. Anything else is treated as empty.

    Returns:
        Set of name strings. Non-string entries are skipped silently --
        they are not the caller's contract violation, just mismatched
        shapes from upstream tools.
    """
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return set()
    names: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            names.add(item)
            continue
        if isinstance(item, dict):
            for key in ("pattern", "name", "type"):
                value = item.get(key)
                if isinstance(value, str):
                    names.add(value)
                    break
    return names


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _score_signature(detection: Any, signature: CffSignature) -> float:
    """Compute the match score for a single signature against detection.

    Args:
        detection: A ``CffDetectionResult``-like object describing what
            the analysis found in the function under inspection.
        signature: The candidate signature to score.

    Returns:
        A score in ``[0.0, 1.0]``. See ``match_signature`` for the
        breakdown.
    """
    score = 0.0

    detected_disp = _detected_dispatchers(detection)
    if detected_disp & set(signature.dispatcher_patterns):
        score += 0.3

    detected_opa = _detected_opaques(detection)
    if detected_opa & set(signature.opaque_patterns):
        score += 0.3

    detected_sv = _detected_state_vars(detection)
    if detected_sv & set(signature.state_var_types):
        score += 0.2

    detected_char = _detected_characteristics(detection)
    char_matches = 0
    for key, expected in signature.characteristics.items():
        # Skip offset-style fields: those vary per-build and shouldn't drive
        # signature matching. Boolean trait keys still count.
        if key == "state_offset":
            continue
        if key in detected_char and detected_char[key] == expected:
            char_matches += 1
    score += min(char_matches * 0.02, 0.2)

    return score


def match_signature(
    detection: CffDetectionResult,
    signatures: list[CffSignature],
) -> tuple[CffSignature | None, float]:
    """Match a CFF detection result against known obfuscator signatures.

    Scoring breakdown:
        * Dispatcher pattern overlap: ``+0.3`` if any detected
          dispatcher name appears in the signature's
          ``dispatcher_patterns``.
        * Opaque-predicate pattern overlap: ``+0.3`` if any detected
          opaque name appears in the signature's ``opaque_patterns``.
          Detections without any classified opaque predicates simply
          forfeit this band -- they are not penalized further.
        * State-variable type overlap: ``+0.2`` if the detected state
          variable kind appears in the signature's ``state_var_types``.
        * Per-characteristic bonuses: ``+0.02`` for each
          ``characteristic`` whose key is present in the detection and
          whose value compares equal, capped at ``+0.2`` total.

    The result is the highest-scoring signature, ties broken by the
    order returned from ``load_signatures``. If no signature meets the
    confidence threshold (currently ``0.5`` -- a dispatcher hit alone is
    too weak to name a family), ``(None, 0.0)`` is returned. Detections
    that resemble nothing in the database must not silently latch onto
    the weakest scorer.

    Args:
        detection: The analysis output to classify. Expected to expose
            ``dispatcher_patterns``, ``opaque_patterns``,
            ``state_var_type`` (or ``state_var_types``), and
            ``characteristics``. Missing fields are treated as "not
            detected", not as errors.
        signatures: Candidate signature list, typically the result of
            ``load_signatures()``. An empty list yields ``(None, 0.0)``.

    Returns:
        ``(best_match, confidence)`` where ``best_match`` is the
        highest-scoring ``CffSignature`` and ``confidence`` is its
        score. ``(None, 0.0)`` when no signature crosses the threshold.
    """
    best: CffSignature | None = None
    best_score = 0.0
    for signature in signatures:
        score = _score_signature(detection, signature)
        if score > best_score:
            best_score = score
            best = signature

    if best is None or best_score < _MATCH_THRESHOLD:
        return (None, 0.0)
    return (best, best_score)



# Module-level registry for use by __init__.load_signatures().
ALL_SIGNATURES = load_signatures()
