"""Binary lifecycle state machine with Gunicorn-style arbiter supervisor.

Each binary progresses through states:
  REGISTERED -> ANALYZING -> READY -> ACTIVE -> INDEXED

The Arbiter thread runs every 2s:
  1. Reaps dead worker processes
  2. Spawns workers for binaries with pending queues
  3. Enforces max_workers via LRU eviction
  4. Staggers cold starts by 3s to avoid idalib DLL race
"""
from __future__ import annotations

import enum
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["BinaryState", "BinaryLifecycle", "LifecycleManager"]

ARBITER_TICK = 2.0       # seconds between supervisor ticks
SPAWN_STAGGER = 0.5      # minimum seconds between spawns (bootstrap is ~0.3s)


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
    """Manages binary lifecycles with arbiter-supervised worker pool."""

    def __init__(self, cache_dir: Path, ida_dir: Path, max_workers: int = 10) -> None:
        self.cache_dir = cache_dir
        self.ida_dir = ida_dir
        self.max_workers = max_workers
        self._lifecycles: dict[str, BinaryLifecycle] = {}
        self._worker_procs: dict[str, subprocess.Popen] = {}
        self._worker_activity: dict[str, float] = {}
        self._last_spawn_time: float = 0.0
        # Arbiter state
        self._arbiter_started = False
        self._arbiter_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Arbiter (supervisor thread)
    # ------------------------------------------------------------------

    def _start_arbiter(self) -> None:
        """Start the arbiter thread if not already running."""
        with self._arbiter_lock:
            if self._arbiter_started:
                return
            self._arbiter_started = True
            t = threading.Thread(target=self._arbiter_loop, daemon=True, name="arbiter")
            t.start()

    def _arbiter_loop(self) -> None:
        """Supervisor loop: reap dead workers, spawn for pending queues.

        Runs every ARBITER_TICK seconds for the lifetime of the server.
        Never exits (daemon thread dies with the server process).
        """
        while True:
            try:
                self._arbiter_tick()
            except Exception:
                pass  # Arbiter must never crash; errors are non-fatal
            time.sleep(ARBITER_TICK)

    def _arbiter_tick(self) -> None:
        """One supervisor cycle: reap, then spawn."""
        # 1. Reap dead workers
        dead_shas = []
        for sha, proc in list(self._worker_procs.items()):
            if proc.poll() is not None:
                dead_shas.append(sha)
        for sha in dead_shas:
            del self._worker_procs[sha]
            self._worker_activity.pop(sha, None)
            # Clean stale heartbeat
            hb = self.cache_dir / sha / "worker_heartbeat.json"
            if hb.exists():
                try:
                    hb.unlink()
                except OSError:
                    pass  # Best-effort cleanup; stale heartbeat may already be gone or locked

        # 2. Find binaries that need workers (have pending queue items)
        needs_worker: list[BinaryLifecycle] = []
        for lc in self._lifecycles.values():
            if lc.state < BinaryState.READY:
                continue
            if lc.sha256 in self._worker_procs:
                continue  # Already has a tracked worker
            # Check queue
            queue = self.cache_dir / lc.sha256 / "request_queue.jsonl"
            if queue.exists():
                try:
                    text = queue.read_text(encoding="utf-8").strip()
                    if text:
                        needs_worker.append(lc)
                except OSError:
                    pass  # Best-effort queue probe; transient I/O errors don't block scheduling

        if not needs_worker:
            return

        # 3. Enforce max_workers — count alive workers
        alive_count = sum(1 for p in self._worker_procs.values() if p.poll() is None)

        # 4. Spawn workers (staggered)
        for lc in needs_worker:
            if alive_count >= self.max_workers:
                # Evict LRU
                if not self._worker_procs:
                    break
                alive_procs = {s: p for s, p in self._worker_procs.items() if p.poll() is None}
                if not alive_procs:
                    break
                lru_sha = min(alive_procs.keys(), key=lambda s: self._worker_activity.get(s, 0))
                self._evict_worker(lru_sha)
                alive_count -= 1

            # Stagger check
            since_last = time.monotonic() - self._last_spawn_time
            if since_last < SPAWN_STAGGER:
                time.sleep(SPAWN_STAGGER - since_last)

            if self._do_spawn(lc):
                alive_count += 1

    def _evict_worker(self, sha: str) -> None:
        """Terminate a worker to make room for a new one."""
        proc = self._worker_procs.get(sha)
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass  # Best-effort kill; process may already be dead
        self._worker_procs.pop(sha, None)
        self._worker_activity.pop(sha, None)
        for lc in self._lifecycles.values():
            if lc.sha256 == sha:
                lc.state = BinaryState.READY
                lc.decompile_worker_pid = None
                self._save(lc)
                break

    # ------------------------------------------------------------------
    # Worker spawning
    # ------------------------------------------------------------------

    def _do_spawn(self, lc: BinaryLifecycle) -> bool:
        """Spawn one worker subprocess. Returns True on success."""
        # Clean lock files before spawn
        workspace = self.cache_dir / lc.sha256 / "workspace"
        if workspace.exists():
            for f in workspace.iterdir():
                if f.suffix in (".id0", ".id1", ".id2", ".nam", ".til"):
                    try:
                        f.unlink()
                    except OSError:
                        pass  # Best-effort lock cleanup; file may be held by another IDA instance

        try:
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
                stderr=subprocess.DEVNULL,
                cwd=src_dir,
                env=env,
            )
            self._worker_procs[lc.sha256] = proc
            self._worker_activity[lc.sha256] = time.monotonic()
            self._last_spawn_time = time.monotonic()
            lc.decompile_worker_pid = proc.pid
            self._save(lc)
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Public API (called by server)
    # ------------------------------------------------------------------

    def ensure_worker(self, binary_id: str) -> str:
        """Signal that a binary needs a worker.

        The arbiter will spawn one on its next tick (within 2s).
        Returns status for the pending response.
        """
        self._start_arbiter()
        lc = self._lifecycles.get(binary_id)
        if not lc or lc.state < BinaryState.READY:
            return "not_ready"

        # Check if already alive
        proc = self._worker_procs.get(lc.sha256)
        if proc is not None and proc.poll() is None:
            self._worker_activity[lc.sha256] = time.monotonic()
            return "alive"

        # Arbiter will pick it up on next tick
        return "queued"

    def _worker_is_alive(self, lc: BinaryLifecycle) -> bool:
        """Check if a worker is running for this binary."""
        proc = self._worker_procs.get(lc.sha256)
        if proc is not None:
            if proc.poll() is None:
                return True
            # Dead — clean up
            del self._worker_procs[lc.sha256]
            self._worker_activity.pop(lc.sha256, None)
            return False

        # Check heartbeat for workers from prior server session
        hb_path = self.cache_dir / lc.sha256 / "worker_heartbeat.json"
        if not hb_path.exists():
            return False
        try:
            hb = json.loads(hb_path.read_text(encoding="utf-8"))
            age = time.time() - hb.get("timestamp", 0)
            pid = hb.get("pid", 0)
            status = hb.get("status", "")

            if status.startswith("exiting"):
                hb_path.unlink(missing_ok=True)
                return False
            if age > 30:
                if pid and _pid_alive(pid):
                    return True
                hb_path.unlink(missing_ok=True)
                return False
            if pid and _pid_alive(pid):
                return True
            hb_path.unlink(missing_ok=True)
            return False
        except (json.JSONDecodeError, OSError, KeyError):
            try:
                hb_path.unlink(missing_ok=True)
            except OSError:
                pass  # Best-effort cleanup; heartbeat file may already be gone
            return False

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
    # Registration
    # ------------------------------------------------------------------

    def register(self, binary_id: str, sha256: str, path: Path, size_bytes: int) -> BinaryLifecycle:
        """Register a binary and start background analysis."""
        import shutil

        self._start_arbiter()

        existing = self._lifecycles.get(binary_id) or self._load(sha256)
        if existing is not None:
            self._lifecycles[binary_id] = existing
            self._reconcile(existing)
            return existing

        workspace = self.cache_dir / sha256 / "workspace"
        workspace_binary = workspace / path.name
        if not workspace_binary.exists():
            workspace.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, workspace_binary)

        lc = BinaryLifecycle(
            binary_id=binary_id, sha256=sha256,
            original_path=str(path), root_filename=path.name,
            size_bytes=size_bytes,
        )
        self._lifecycles[binary_id] = lc
        self._save(lc)
        self._start_analysis(lc)
        return lc

    # ------------------------------------------------------------------
    # Background analysis
    # ------------------------------------------------------------------

    def _start_analysis(self, lc: BinaryLifecycle) -> None:
        """Spawn idat64 -B to pre-create .i64 in background."""
        if lc.state >= BinaryState.READY:
            return
        workspace = self.cache_dir / lc.sha256 / "workspace"
        workspace_binary = workspace / lc.root_filename
        if not workspace_binary.exists():
            return
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
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            lc.state = BinaryState.ANALYZING
            lc.analyzer_pid = proc.pid
            self._save(lc)
        except OSError as exc:
            lc.error = f"Failed to start idat64: {exc}"
            self._save(lc)

    def poll_analysis(self, binary_id: str) -> BinaryState:
        """Check if background analysis completed."""
        lc = self._lifecycles.get(binary_id)
        if lc is None:
            raise KeyError(f"Unknown binary_id: {binary_id}")
        self._reconcile(lc)
        return lc.state

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------

    def _reconcile(self, lc: BinaryLifecycle) -> None:
        """Reconcile persisted state with filesystem reality."""
        workspace = self.cache_dir / lc.sha256 / "workspace"
        i64_files = list(workspace.glob("*.i64")) if workspace.exists() else []

        if lc.state == BinaryState.ANALYZING:
            if i64_files:
                lc.state = BinaryState.READY
                lc.analyzer_pid = None
                self._save(lc)
            elif lc.analyzer_pid is not None:
                if not _pid_alive(lc.analyzer_pid):
                    lc.state = BinaryState.REGISTERED
                    lc.analyzer_pid = None
                    self._save(lc)
                    self._start_analysis(lc)
        elif lc.state >= BinaryState.READY and not i64_files:
            lc.state = BinaryState.REGISTERED
            self._save(lc)
            self._start_analysis(lc)

    # ------------------------------------------------------------------
    # State promotion
    # ------------------------------------------------------------------

    def ensure_state(self, binary_id: str, target: BinaryState) -> BinaryLifecycle:
        """Promote a binary to at least the target state, blocking if needed."""
        lc = self._lifecycles.get(binary_id)
        if lc is None:
            raise KeyError(f"Unknown binary_id: {binary_id}")
        self._reconcile(lc)
        if lc.state == BinaryState.ANALYZING and target >= BinaryState.READY:
            self._wait_for_analysis(lc, timeout=600)
        if lc.state < BinaryState.READY and target >= BinaryState.READY:
            self._start_analysis(lc)
            self._wait_for_analysis(lc, timeout=600)
        return lc

    def _wait_for_analysis(self, lc: BinaryLifecycle, timeout: float = 600) -> None:
        """Block until .i64 appears or timeout."""
        workspace = self.cache_dir / lc.sha256 / "workspace"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if list(workspace.glob("*.i64")):
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
        self._start_arbiter()
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
        # Arbiter will handle spawning workers for pending queues
        return recovered

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get(self, binary_id: str) -> BinaryLifecycle | None:
        return self._lifecycles.get(binary_id)

    def all(self) -> list[BinaryLifecycle]:
        return list(self._lifecycles.values())

    def workspace_binary(self, lc: BinaryLifecycle) -> Path:
        return self.cache_dir / lc.sha256 / "workspace" / lc.root_filename


def _pid_alive(pid: int) -> bool:
    """Check if a process is actually running.

    On Windows, uses GetExitCodeProcess to check for STILL_ACTIVE (259).
    OpenProcess(SYNCHRONIZE) is unreliable — succeeds on dead processes.
    """
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
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
