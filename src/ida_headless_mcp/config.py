"""Runtime configuration loaded from environment variables.

Resolves IDA, project, and cache directory paths plus a few tunables
from ``IDA_HEADLESS_MCP_*`` environment variables, applying defaults
when they are unset.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Settings", "load_settings"]


@dataclass(frozen=True, slots=True)
class Settings:
    """Resolved runtime settings for the IDA Headless MCP server.

    Attributes:
        ida_dir: Filesystem path to the IDA installation directory.
        project_dir: Directory used to store IDA projects.
        cache_dir: Directory used for the shared analysis cache.
        max_binary_size_mb: Upper bound on accepted binary size, in megabytes.
        idle_timeout_s: Seconds an idle binary stays loaded before being closed.
        max_concurrent_ida: Maximum number of concurrent IDA processes.
    """
    ida_dir: Path
    project_dir: Path
    cache_dir: Path
    max_binary_size_mb: int = 200
    idle_timeout_s: int = 900
    max_concurrent_ida: int = 3  # idalib GIL + I/O contention limits concurrency


def _env_path(name: str, default: Path) -> Path:
    """Read a path from an environment variable, falling back to ``default``.

    Args:
        name: Environment variable name.
        default: Path returned when the variable is unset or blank.

    Returns:
        The configured path, or ``default`` when no override is set.
    """
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else default


def _env_int(name: str, default: int) -> int:
    """Read an integer from an environment variable, falling back to ``default``.

    Args:
        name: Environment variable name.
        default: Value returned when the variable is unset or blank.

    Returns:
        The parsed integer, or ``default`` when no override is set.

    Raises:
        ValueError: If the variable is set to a non-integer value.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def load_settings() -> Settings:
    """Build a :class:`Settings` instance from environment variables.

    Resolves project and cache directories to absolute paths and creates
    them on disk if they do not already exist.

    Returns:
        A populated :class:`Settings` value with all directories materialised.
    """
    # Platform-appropriate default IDA directory
    if sys.platform == "darwin":
        default_ida = Path("/Applications/IDA Professional 9.3.app/Contents/MacOS")
    elif sys.platform == "linux":
        default_ida = Path("/opt/ida-pro-9.0")
    else:
        default_ida = Path(r"C:/Program Files/IDA Professional 9.0")
    ida_dir = _env_path("IDA_HEADLESS_MCP_IDA_DIR", default_ida)
    project_dir = _env_path("IDA_HEADLESS_MCP_PROJECT_DIR", Path("projects"))
    cache_dir = _env_path("IDA_HEADLESS_MCP_CACHE_DIR", Path("cache"))
    settings = Settings(
        ida_dir=ida_dir.resolve(),
        project_dir=project_dir.resolve(),
        cache_dir=cache_dir.resolve(),
        max_binary_size_mb=_env_int("IDA_HEADLESS_MCP_MAX_BINARY_SIZE_MB", 200),
        idle_timeout_s=_env_int("IDA_HEADLESS_MCP_IDLE_TIMEOUT_S", 900),
        max_concurrent_ida=_env_int("IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA", 3),
    )
    settings.project_dir.mkdir(parents=True, exist_ok=True)
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    return settings
