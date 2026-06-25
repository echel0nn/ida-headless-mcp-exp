"""HTTP API exposing every registered MCP tool as a POST endpoint.

Introspects ``server.mcp._tool_manager._tools`` at app-build time and wires
each tool to ``POST /tools/{tool_name}``. Tool functions are sync; FastAPI
runs sync handlers in a thread pool, so the underlying ``_fe()`` cache and
lifecycle (already thread-safe) stay consistent with stdio/sse transports.

The same ``mcp`` and ``_fe()`` singletons are shared with the stdio server,
so HTTP and stdio callers see one cache, one lifecycle, one set of binaries.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, UploadFile

from .server import _fe, mcp, open_binary

__all__ = ["create_app", "run_http"]

# Errors that map to a JSON envelope with HTTP 200. Callers expect the
# ``{"status": "error", "error": ...}`` envelope rather than an HTTP 5xx,
# matching how stdio tools surface failures inside the result dict.
_TOOL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    RuntimeError,
    KeyError,
    TypeError,
    OSError,
    FileNotFoundError,
)


def _tool_index() -> dict[str, Any]:
    """Live view of every ``@mcp.tool()``-registered tool."""
    return mcp._tool_manager._tools  # noqa: SLF001 — public surface of FastMCP


def _make_handler(fn: Callable[..., Any], tool_name: str) -> Callable[..., Any]:
    """Build a FastAPI POST handler that proxies a single tool function."""

    def handler(payload: dict[str, Any] | None = Body(default=None)) -> Any:
        params = payload if payload is not None else {}
        if not isinstance(params, dict):
            return {
                "status": "error",
                "error": (
                    f"Tool {tool_name} expects a JSON object body; "
                    f"got {type(params).__name__}"
                ),
            }
        try:
            return fn(**params)
        except _TOOL_EXCEPTIONS as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    handler.__name__ = f"call_{tool_name}"
    return handler


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Warm the frontend singleton so the first request doesn't pay
    # lifecycle-recovery cost (and so startup failures surface immediately).
    _fe()
    yield


def create_app() -> FastAPI:
    """Build a FastAPI app with one POST route per MCP tool."""
    app = FastAPI(
        title="IDA Headless MCP — HTTP API",
        description="HTTP transport mirroring the MCP stdio tool surface.",
        version="0.1.0",
        lifespan=_lifespan,
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "tools": len(_tool_index())}

    @app.get("/tools")
    def list_tools() -> list[dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            }
            for tool in _tool_index().values()
        ]

    @app.post("/upload", summary="Upload a binary for analysis")
    async def upload_binary(file: UploadFile) -> dict[str, Any]:
        """Upload a binary file. Saves to temp dir, calls open_binary."""
        if not file.filename:
            return {"status": "error", "error": "No filename in upload"}
        suffix = Path(file.filename).suffix or ""
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=suffix, prefix="ida_upload_",
            ) as tmp:
                while chunk := await file.read(1024 * 1024):
                    tmp.write(chunk)
                tmp_path = tmp.name
            result = open_binary(tmp_path)
            return result
        except _TOOL_EXCEPTIONS as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        finally:
            try:
                os.unlink(tmp_path)  # type: ignore[possibly-undefined]
            except (OSError, UnboundLocalError):
                pass  # best-effort cleanup; workspace copy already made by open_binary

    for name, tool in _tool_index().items():
        if tool.is_async:
            # Current server is fully sync; fail loudly the day someone
            # registers an async tool so we update the dispatcher together.
            raise RuntimeError(
                f"Async tools are not supported by the HTTP transport: {name}"
            )
        summary = (tool.description or name).strip().splitlines()[0]
        app.add_api_route(
            path=f"/tools/{name}",
            endpoint=_make_handler(tool.fn, name),
            methods=["POST"],
            name=name,
            summary=summary[:120],
            response_model=None,  # tools return dict OR list — let JSON encode
        )

    return app


def run_http() -> None:
    """Run the HTTP API server with uvicorn.

    Host: ``IDA_HEADLESS_HTTP_HOST`` (default ``127.0.0.1``).
    Port: ``IDA_HEADLESS_HTTP_PORT`` (default ``18821``).
    """
    import uvicorn  # local import: stdio path doesn't need uvicorn loaded

    host = os.environ.get("IDA_HEADLESS_HTTP_HOST", "127.0.0.1")
    port = int(os.environ.get("IDA_HEADLESS_HTTP_PORT", "18821"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
