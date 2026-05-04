"""Binary lifecycle state machine — durable, crash-proof analysis pipeline.

Each binary progresses through states:
  REGISTERED → ANALYZING → READY → ACTIVE → INDEXED

State is persisted to cache/{sha}/state.json. On server restart, all
binaries resume from their last persisted state. Background analysis
(idat64 -B) runs asynchronously — open_binary returns instantly.
"""
from __future__ import annotations

import enum
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["BinaryState", "BinaryLifecycle", "LifecycleManager"]


class BinaryState(enum.IntEnum):
    """Binary analysis lifecycle states, ordered by completeness."""
    REGISTERED = 0   # PE header parsed, workspace created
    ANALYZING = 1    # idat64 -B running in background
    READY = 2        # .i64 exists, not loaded in idalib
    ACTIVE = 3       # idalib has .i64 loaded in-process
    INDEXED = 4      # function index built and cached


@dataclass
class BinaryLifecycle:
    """Durable state for one binary."""
    binary_id: str
    sha256: str
    original_path: str
    root_filename: str
    size_bytes: int
    state: BinaryState = BinaryState.REGISTERED
    analyzer_pid: int | None = None
    decompile_worker_pid: int | None = None
    function_count: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_id": self.binary_id,
            "sha256": self.sha256,
            "original_path": self.original_path,
            "root_filename": self.root_filename,
            "size_bytes": self.size_bytes,
            "state": self.state.name,
            "analyzer_pid": self.analyzer_pid,
            "decompile_worker_pid": self.decompile_worker_pid,
            "function_count": self.function_count,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BinaryLifecycle:
        return cls(
            binary_id=data["binary_id"],
            sha256=data["sha256"],
            original_path=data["original_path"],
            root_filename=data["root_filename"],
            size_bytes=data["size_bytes"],
            state=BinaryState[data["state"]],
            analyzer_pid=data.get("analyzer_pid"),
            decompile_worker_pid=data.get("decompile_worker_pid"),
            function_count=data.get("function_count", 0),
            error=data.get("error"),
        )


class LifecycleManager:
    """Manages binary lifecycles with persistent state and background analysis."""

    def __init__(self, cache_dir: Path, ida_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.ida_dir = ida_dir
        self._lifecycles: dict[str, BinaryLifecycle] = {}

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _state_path(self, sha256: str) -> Path:
        return self.cache_dir / sha256 / "state.json"

    def _save(self, lc: BinaryLifecycle) -> None:
        path = self._state_path(lc.sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(lc.to_dict(), indent=2), encoding="utf-8")

    def _load(self, sha256: str) -> BinaryLifecycle | None:
        path = self._state_path(sha256)
        if not path.exists():
            return None
        try:
            return BinaryLifecycle.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    # ------------------------------------------------------------------
    # Registration (instant)
    # ------------------------------------------------------------------

    def register(self, binary_id: str, sha256: str, path: Path, size_bytes: int) -> BinaryLifecycle:
        """Register a binary. Copies to workspace. Returns instantly."""
        import shutil

        # Check if already known
        existing = self._lifecycles.get(binary_id) or self._load(sha256)
        if existing is not None:
            self._lifecycles[binary_id] = existing
            # Re-validate state based on what actually exists on disk
            self._reconcile(existing)
            return existing

        # Copy to workspace
        workspace = self.cache_dir / sha256 / "workspace"
        workspace_binary = workspace / path.name
        if not workspace_binary.exists():
            workspace.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, workspace_binary)

        lc = BinaryLifecycle(
            binary_id=binary_id,
            sha256=sha256,
            original_path=str(path),
            root_filename=path.name,
            size_bytes=size_bytes,
        )
        self._lifecycles[binary_id] = lc
        self._save(lc)

        # Auto-start background analysis
        self._start_analysis(lc)
        return lc

    # ------------------------------------------------------------------
    # Background analysis (async)
    # ------------------------------------------------------------------

    def _start_analysis(self, lc: BinaryLifecycle) -> None:
        """Spawn idat64 -B to pre-create .i64 in background."""
        if lc.state >= BinaryState.READY:
            return  # already analyzed

        workspace = self.cache_dir / lc.sha256 / "workspace"
        workspace_binary = workspace / lc.root_filename
        if not workspace_binary.exists():
            return

        # Check if .i64 already exists (maybe from prior run)
        i64 = workspace / f"{lc.root_filename}.i64"
        if i64.exists():
            lc.state = BinaryState.READY
            self._save(lc)
            return

        idat = self.ida_dir / "idat64.exe"
        if not idat.exists():
            lc.error = "idat64.exe not found"
            self._save(lc)
            return

        try:
            proc = subprocess.Popen(
                [str(idat), "-A", "-B", str(workspace_binary)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            lc.state = BinaryState.ANALYZING
            lc.analyzer_pid = proc.pid
            self._save(lc)
        except OSError as exc:
            lc.error = f"Failed to start idat64: {exc}"
            self._save(lc)

    def _start_binary_worker(self, lc: BinaryLifecycle) -> None:
        """Spawn the unified binary worker for this binary."""
        if lc.decompile_worker_pid is not None and _pid_alive(lc.decompile_worker_pid):
            return  # already running

        try:
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "ida_headless_mcp.binary_worker",
                    "--sha256", lc.sha256,
                    "--cache-dir", str(self.cache_dir),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            lc.decompile_worker_pid = proc.pid
            self._save(lc)
        except OSError:
            pass

    def poll_analysis(self, binary_id: str) -> BinaryState:
        """Check if background analysis completed."""
        lc = self._lifecycles.get(binary_id)
        if lc is None:
            raise KeyError(f"Unknown binary_id: {binary_id}")
        self._reconcile(lc)
        return lc.state

    # ------------------------------------------------------------------
    # State reconciliation (crash recovery)
    # ------------------------------------------------------------------

    def _reconcile(self, lc: BinaryLifecycle) -> None:
        """Reconcile persisted state with filesystem reality."""
        workspace = self.cache_dir / lc.sha256 / "workspace"
        i64_files = list(workspace.glob("*.i64")) if workspace.exists() else []

        if lc.state == BinaryState.ANALYZING:
            # Check if .i64 appeared (analysis completed)
            if i64_files:
                lc.state = BinaryState.READY
                lc.analyzer_pid = None
                self._save(lc)
                self._start_binary_worker(lc)
            elif lc.analyzer_pid is not None:
                # Check if the process is still alive
                if not _pid_alive(lc.analyzer_pid):
                    # Process died without producing .i64 — restart
                    lc.state = BinaryState.REGISTERED
                    lc.analyzer_pid = None
                    self._save(lc)
                    self._start_analysis(lc)

        elif lc.state >= BinaryState.READY and not i64_files:
            # .i64 was deleted (cache eviction?) — downgrade
            lc.state = BinaryState.REGISTERED
            self._save(lc)
            self._start_analysis(lc)

    # ------------------------------------------------------------------
    # State promotion (blocking)
    # ------------------------------------------------------------------

    def ensure_state(self, binary_id: str, target: BinaryState) -> BinaryLifecycle:
        """Promote a binary to at least the target state, blocking if needed."""
        lc = self._lifecycles.get(binary_id)
        if lc is None:
            raise KeyError(f"Unknown binary_id: {binary_id}")

        self._reconcile(lc)

        # Wait for background analysis if needed
        if lc.state == BinaryState.ANALYZING and target >= BinaryState.READY:
            self._wait_for_analysis(lc, timeout=600)

        if lc.state < BinaryState.READY and target >= BinaryState.READY:
            # No .i64, no background analysis — do synchronous analysis
            self._start_analysis(lc)
            self._wait_for_analysis(lc, timeout=600)

        return lc

    def _wait_for_analysis(self, lc: BinaryLifecycle, timeout: float = 600) -> None:
        """Block until .i64 appears or timeout."""
        workspace = self.cache_dir / lc.sha256 / "workspace"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            i64_files = list(workspace.glob("*.i64"))
            if i64_files:
                lc.state = BinaryState.READY
                lc.analyzer_pid = None
                self._save(lc)
                return
            time.sleep(0.5)
        lc.error = "Analysis timeout"
        self._save(lc)

    # ------------------------------------------------------------------
    # Recovery on startup
    # ------------------------------------------------------------------

    def recover_all(self) -> list[BinaryLifecycle]:
        """Scan cache for persisted binary states and recover them."""
        recovered = []
        if not self.cache_dir.exists():
            return recovered
        for sha_dir in self.cache_dir.iterdir():
            if not sha_dir.is_dir() or len(sha_dir.name) != 64:
                continue
            lc = self._load(sha_dir.name)
            if lc is not None:
                self._reconcile(lc)
                self._lifecycles[lc.binary_id] = lc
                recovered.append(lc)
        return recovered

    def get(self, binary_id: str) -> BinaryLifecycle | None:
        return self._lifecycles.get(binary_id)

    def all(self) -> list[BinaryLifecycle]:
        return list(self._lifecycles.values())

    def workspace_binary(self, lc: BinaryLifecycle) -> Path:
        return self.cache_dir / lc.sha256 / "workspace" / lc.root_filename


def _pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
