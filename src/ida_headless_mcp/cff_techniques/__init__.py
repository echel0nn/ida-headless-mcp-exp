"""CFF (Control-Flow Flattening) technique database.

Public surface:
    - Base classes: ``DispatcherPattern``, ``OpaquePredicatePattern``,
      ``StateVariableDetector``.
    - Result types: ``BlockInfo``, ``StateVarInfo``, ``CffSignature``,
      ``CffDetectionResult``, ``DeflattedState``, ``DeflattedFunction``.
    - Loader functions: ``load_dispatchers``, ``load_opaque_patterns``,
      ``load_state_var_detectors``, ``load_signatures``.

The loader functions defer their imports of the sibling implementation
modules so that ``from ida_headless_mcp.cff_techniques import *`` succeeds
even when those modules have not been written yet. Each implementation
module is expected to expose an ``ALL_<KIND>`` list of instances.
"""
from __future__ import annotations

from ._types import (
    BlockInfo,
    CffDetectionResult,
    CffSignature,
    DeflattedFunction,
    DeflattedState,
    DispatcherPattern,
    OpaquePredicatePattern,
    StateVarInfo,
    StateVariableDetector,
)

__all__ = [
    "BlockInfo",
    "CffDetectionResult",
    "CffSignature",
    "DeflattedFunction",
    "DeflattedState",
    "DispatcherPattern",
    "OpaquePredicatePattern",
    "StateVarInfo",
    "StateVariableDetector",
    "load_dispatchers",
    "load_opaque_patterns",
    "load_state_var_detectors",
    "load_signatures",
    "load_techniques",
]


def load_dispatchers() -> list[DispatcherPattern]:
    """Return instances of every registered dispatcher pattern.

    Reads the ``ALL_DISPATCHERS`` attribute from the sibling
    ``dispatchers`` module. The import is deferred so that this package
    remains importable while ``dispatchers`` is still being authored.
    """
    from . import dispatchers  # deferred: sibling module is authored separately

    return list(dispatchers.ALL_DISPATCHERS)


def load_opaque_patterns() -> list[OpaquePredicatePattern]:
    """Return instances of every registered opaque-predicate pattern.

    Reads the ``ALL_OPAQUE_PATTERNS`` attribute from the sibling
    ``opaque_predicates`` module.
    """
    from . import opaque_predicates  # deferred for the same reason

    return list(opaque_predicates.ALL_OPAQUE_PATTERNS)


def load_state_var_detectors() -> list[StateVariableDetector]:
    """Return instances of every registered state-variable detector.

    Reads the ``ALL_STATE_VAR_DETECTORS`` attribute from the sibling
    ``state_variables`` module.
    """
    from . import state_variables  # deferred for the same reason

    return list(state_variables.ALL_STATE_VAR_DETECTORS)


def load_signatures() -> list[CffSignature]:
    """Return all known obfuscator fingerprints.

    Reads the ``ALL_SIGNATURES`` attribute from the sibling ``signatures``
    module.
    """
    from . import signatures  # deferred for the same reason

    return list(signatures.ALL_SIGNATURES)



def load_techniques() -> dict:
    """Return all technique detectors grouped by kind.

    Returns:
        Dict with keys ``dispatchers``, ``opaque_predicates``,
        ``state_variables``, ``signatures``.
    """
    return {
        "dispatchers": load_dispatchers(),
        "opaque_predicates": load_opaque_patterns(),
        "state_variables": load_state_var_detectors(),
        "signatures": load_signatures(),
    }
