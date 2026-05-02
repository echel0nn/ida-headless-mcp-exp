from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Settings", "load_settings"]


@dataclass(frozen=True, slots=True)
class Settings:
    ida_dir: Path
    project_dir: Path
    cache_dir: Path
    max_binary_size_mb: int = 200
    idle_timeout_s: int = 900
    max_concurrent_ida: int = 2


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def load_settings() -> Settings:
    ida_dir = _env_path("IDA_HEADLESS_MCP_IDA_DIR", Path(r"C:/Program Files/IDA Professional 9.0"))
    project_dir = _env_path("IDA_HEADLESS_MCP_PROJECT_DIR", Path("projects"))
    cache_dir = _env_path("IDA_HEADLESS_MCP_CACHE_DIR", Path("cache"))
    settings = Settings(
        ida_dir=ida_dir.resolve(),
        project_dir=project_dir.resolve(),
        cache_dir=cache_dir.resolve(),
        max_binary_size_mb=_env_int("IDA_HEADLESS_MCP_MAX_BINARY_SIZE_MB", 200),
        idle_timeout_s=_env_int("IDA_HEADLESS_MCP_IDLE_TIMEOUT_S", 900),
        max_concurrent_ida=_env_int("IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA", 2),
    )
    settings.project_dir.mkdir(parents=True, exist_ok=True)
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    return settings
