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

    def __init__(self, cache_dir: Path, ida_dir: Path, max_workers: int = 4) -> None:
        self.cache_dir = cache_dir
        self.ida_dir = ida_dir
        self.max_workers = max_workers
        self._lifecycles: dict[str, BinaryLifecycle] = {}
        self._worker_procs: dict[str, subprocess.Popen] = {}
        self._worker_activity: dict[str, float] = {}  # sha256 -> last activity time

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
        """Register a binary and start background analysis.

        Copies the binary into its workspace and kicks off ``idat64 -B``
        asynchronously. Returns instantly; the binary may still be
        ``REGISTERED`` or ``ANALYZING`` on return.

        Args:
            binary_id: Caller-chosen identifier for the binary.
            sha256: SHA-256 hash of the binary's contents.
            path: Filesystem path to the source binary.
            size_bytes: Size of the binary in bytes.

        Returns:
            The :class:`BinaryLifecycle` for this binary, either freshly
            created or recovered from a prior session.
        """
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

    def ensure_worker(self, binary_id: str) -> str:
        """Ensure a worker is running for the given binary.

        Returns a status string describing what happened:
        - 'alive': worker was already running
        - 'spawned': new worker started
        - 'respawned': dead worker replaced with new one
        - 'not_ready': binary not yet analyzed (.i64 missing)
        - 'spawn_failed': subprocess failed to start (check logs)
        """
        lc = self._lifecycles.get(binary_id)
        if not lc or lc.state < BinaryState.READY:
            return "not_ready"
        return self._start_binary_worker(lc)

    def _worker_is_alive(self, lc: BinaryLifecycle) -> bool:
        """Definitive liveness check for a binary's worker.

        Checks in order:
        1. Tracked subprocess object (most reliable)
        2. Heartbeat file with PID validation (for workers from prior server)
        """
        # Check tracked subprocess
        existing = self._worker_procs.get(lc.sha256)
        if existing is not None:
            if existing.poll() is None:
                return True  # Definitely alive
            # Dead — clean up stale entry
            del self._worker_procs[lc.sha256]
            self._worker_activity.pop(lc.sha256, None)
            return False

        # No tracked proc — check heartbeat (for workers surviving server restart)
        hb_path = self.cache_dir / lc.sha256 / "worker_heartbeat.json"
        if not hb_path.exists():
            return False
        try:
            hb = json.loads(hb_path.read_text(encoding="utf-8"))
            age = time.time() - hb.get("timestamp", 0)
            pid = hb.get("pid", 0)
            status = hb.get("status", "")

            # If heartbeat says exiting, it's dead
            if status.startswith("exiting"):
                hb_path.unlink(missing_ok=True)
                return False

            # Stale heartbeat (>30s) means worker is dead or hung
            if age > 30:
                # Double-check with OS-level PID probe
                if pid and _pid_alive(pid):
                    return True  # Worker alive, just missed heartbeat
                hb_path.unlink(missing_ok=True)
                return False

            # Fresh heartbeat — verify PID is real
            if pid and _pid_alive(pid):
                return True
            hb_path.unlink(missing_ok=True)
            return False
        except (json.JSONDecodeError, OSError, KeyError):
            hb_path.unlink(missing_ok=True)
            return False

    def _start_binary_worker(self, lc: BinaryLifecycle) -> str:
        """Spawn a binary_worker process for this binary.

        Returns 'alive', 'spawned', 'respawned', or 'spawn_failed'.
        Enforces max_workers limit via LRU eviction.
        """
        was_dead = not self._worker_is_alive(lc)
        if not was_dead:
            self._worker_activity[lc.sha256] = time.monotonic()
            return "alive"

        # Enforce max_workers — evict LRU if at capacity
        alive = {
            sha: proc for sha, proc in self._worker_procs.items()
            if proc.poll() is None
        }
        # Clean up dead entries
        dead = [sha for sha, proc in self._worker_procs.items() if proc.poll() is not None]
        for sha in dead:
            del self._worker_procs[sha]
            self._worker_activity.pop(sha, None)

        if len(alive) >= self.max_workers:
            lru_sha = min(
                alive.keys(),
                key=lambda s: self._worker_activity.get(s, 0),
            )
            lru_proc = alive[lru_sha]
            try:
                lru_proc.terminate()
                lru_proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                lru_proc.kill()
            del self._worker_procs[lru_sha]
            self._worker_activity.pop(lru_sha, None)
            for evicted in self._lifecycles.values():
                if evicted.sha256 == lru_sha:
                    evicted.state = BinaryState.READY
                    evicted.decompile_worker_pid = None
                    self._save(evicted)
                    break

        # Spawn new worker with stderr logged
        log_dir = self.cache_dir / lc.sha256 / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "worker_stderr.log"
        try:
            stderr_fh = open(log_file, "a", encoding="utf-8")
            # Ensure the worker can find ida_headless_mcp package
            src_dir = str(Path(__file__).resolve().parent.parent)
            env = dict(os.environ)
            pp = env.get("PYTHONPATH", "")
            if src_dir not in pp:
                env["PYTHONPATH"] = src_dir + (os.pathsep + pp if pp else "")
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "ida_headless_mcp.binary_worker",
                    "--sha256", lc.sha256,
                    "--cache-dir", str(self.cache_dir),
                ],
                stdout=subprocess.DEVNULL,
                stderr=stderr_fh,
                cwd=src_dir,
                env=env,
            )
            self._worker_procs[lc.sha256] = proc
            self._worker_activity[lc.sha256] = time.monotonic()
            lc.decompile_worker_pid = proc.pid
            self._save(lc)
            return "respawned" if was_dead else "spawned"
        except OSError as exc:
            import traceback
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n[lifecycle] Failed to spawn worker: {exc}\n")
                f.write(traceback.format_exc())
            return "spawn_failed"

    def check_workers(self) -> dict[str, str]:
        """Check worker health. Restart dead workers for READY+ binaries."""
        report: dict[str, str] = {}
        for sha, proc in list(self._worker_procs.items()):
            if proc.poll() is not None:
                lc = next((lf for lf in self._lifecycles.values() if lf.sha256 == sha), None)
                if lc and lc.state >= BinaryState.READY:
                    self._start_binary_worker(lc)
                    report[sha[:12]] = "restarted"
                else:
                    del self._worker_procs[sha]
                    report[sha[:12]] = "removed"
            else:
                report[sha[:12]] = "alive"
        return report

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
                # Start worker if there are pending requests in queue
                queue = sha_dir / "request_queue.jsonl"
                has_pending = queue.exists() and queue.stat().st_size > 0
                if lc.state >= BinaryState.READY and has_pending:
                    self._start_binary_worker(lc)
                recovered.append(lc)
        return recovered

    def get(self, binary_id: str) -> BinaryLifecycle | None:
        return self._lifecycles.get(binary_id)

    def all(self) -> list[BinaryLifecycle]:
        return list(self._lifecycles.values())

    def workspace_binary(self, lc: BinaryLifecycle) -> Path:
        return self.cache_dir / lc.sha256 / "workspace" / lc.root_filename


def _pid_alive(pid: int) -> bool:
    """Check if a process is actually running (not just a stale handle).

    On Windows, OpenProcess(SYNCHRONIZE) succeeds on dead processes.
    Use GetExitCodeProcess to check for STILL_ACTIVE (259).
    """
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                # STILL_ACTIVE = 259 (0x103)
                return exit_code.value == 259
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False