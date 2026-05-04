"""State guards for MCP tool methods.

A decorator that declares the minimum lifecycle state a tool needs.
If the binary isn't at that state yet, returns a pending response
instead of blocking or crashing.

Usage:
    class SessionManager:
        @requires(BinaryState.ACTIVE)
        def decompile(self, binary_id, ...):
            ...  # IDA is guaranteed open when this runs

        @requires(BinaryState.INDEXED)
        def search_pattern(self, binary_id, ...):
            ...  # index is guaranteed loaded when this runs

        @requires(None)  # no IDA needed
        def checksec(self, binary_id, ...):
            ...
"""
from __future__ import annotations

import functools
from typing import Any

from .lifecycle import BinaryState

__all__ = ["requires"]


def requires(min_state: BinaryState | None):
    """Decorator: declare the minimum lifecycle state a tool method needs.

    If the binary hasn't reached that state, returns {"status": "pending"}
    instantly. If it has, promotes to the required state and runs the method.
    """
    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, binary_id: str, *args: Any, **kwargs: Any) -> Any:
            if min_state is None:
                # No IDA needed — just check the binary exists
                self._require(binary_id)
                return method(self, binary_id, *args, **kwargs)

            # Check lifecycle state
            lc = self._lifecycle.get(binary_id)
            if lc is None:
                return {
                    "binary_id": binary_id,
                    "status": "error",
                    "message": f"Unknown binary_id: {binary_id}. Call open_binary first.",
                }
            self._lifecycle._reconcile(lc)

            if lc.state < BinaryState.READY:
                return {
                    "binary_id": binary_id,
                    "status": "pending",
                    "state": lc.state.name,
                    "message": "Background analysis in progress. Poll with poll_analysis().",
                }

            # Binary is at least READY. Promote to required state.
            if min_state >= BinaryState.ACTIVE:
                try:
                    self._activate(binary_id)
                except RuntimeError as exc:
                    return {
                        "binary_id": binary_id,
                        "status": "pending",
                        "state": lc.state.name,
                        "message": str(exc),
                    }

            if min_state >= BinaryState.INDEXED:
                try:
                    self._ensure_indexed(binary_id)
                except RuntimeError as exc:
                    return {
                        "binary_id": binary_id,
                        "status": "pending",
                        "state": "INDEXING",
                        "message": str(exc),
                    }

            return method(self, binary_id, *args, **kwargs)

        # Store the requirement for introspection
        wrapper._min_state = min_state
        return wrapper
    return decorator
