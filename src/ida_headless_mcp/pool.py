"""Worker pool — spawns multiple idalib subprocesses for concurrent binary analysis."""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings

__all__ = ["WorkerPool"]


@dataclass
class _Worker:
    proc: subprocess.Popen
    pid: int
    binary_id: str | None = None
    last_activity: float = field(default_factory=time.monotonic)
    _stdout_q: queue.Queue = field(default_factory=queue.Queue)
    _reader_thread: threading.Thread | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, method: str, params: dict, msg_id: int) -> dict:
        """Send a JSON-RPC request and wait for the response.

        Args:
            method: JSON-RPC method name.
            params: JSON-RPC parameters.
            msg_id: Request id used to match the response.

        Returns:
            The decoded JSON-RPC response with matching ``id``.

        Raises:
            RuntimeError: If the worker process dies or closes stdout.
            TimeoutError: If no matching response arrives within the deadline.
        """
        with self._lock:
            msg = json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params})
            self.proc.stdin.write((msg + "\n").encode("utf-8"))
            self.proc.stdin.flush()
            self.last_activity = time.monotonic()

            # Wait for response with matching id
            deadline = time.monotonic() + 600  # 10 min max per call
            while time.monotonic() < deadline:
                try:
                    line = self._stdout_q.get(timeout=1.0)
                except queue.Empty:
                    if self.proc.poll() is not None:
                        raise RuntimeError(f"Worker {self.pid} died during request")
                    continue
                if line is None:
                    raise RuntimeError(f"Worker {self.pid} closed stdout")
                try:
                    resp = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if resp.get("id") == msg_id:
                    return resp
                # Skip notifications (worker/ready, etc.)
            raise TimeoutError(f"Worker {self.pid} timed out on method={method}")

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_activity


class WorkerPool:
    """Manages a pool of idalib worker subprocesses.

    Each worker holds one binary warm. The pool routes requests by binary_id
    affinity — if a worker already has binary X loaded, all requests for X
    go to that worker. New binaries get assigned to idle workers or trigger
    new worker spawns (up to max_workers).
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.max_workers = settings.max_concurrent_ida
        self.idle_timeout = settings.idle_timeout_s
        self._workers: list[_Worker] = []
        self._affinity: dict[str, _Worker] = {}  # binary_id -> worker
        self._msg_id = 0
        self._lock = threading.Lock()

    def call(self, method: str, params: dict[str, Any]) -> Any:
        """Route a method call to the appropriate worker.

        Args:
            method: JSON-RPC method name.
            params: JSON-RPC parameters; ``binary_id`` selects worker affinity.

        Returns:
            The ``result`` field of the worker's JSON-RPC response.

        Raises:
            RuntimeError: If the worker returns an error.
        """
        binary_id = params.get("binary_id") or params.get("binary_id_old")

        with self._lock:
            self._msg_id += 1
            msg_id = self._msg_id

            # Find or assign worker
            worker = self._get_worker(method, params, binary_id)

        resp = worker.send(method, params, msg_id)

        if "error" in resp:
            err = resp["error"]
            raise RuntimeError(f"Worker error: {err.get('message', err)}")

        result = resp.get("result")

        # Track affinity for open_binary
        if method == "open_binary" and result and "binary_id" in result:
            with self._lock:
                self._affinity[result["binary_id"]] = worker
                worker.binary_id = result["binary_id"]

        return result

    def shutdown(self) -> None:
        """Terminate all workers."""
        for w in self._workers:
            try:
                w.proc.terminate()
                w.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                w.proc.kill()
        self._workers.clear()
        self._affinity.clear()

    def status(self) -> dict[str, Any]:
        """Return pool status."""
        return {
            "max_workers": self.max_workers,
            "active_workers": len([w for w in self._workers if w.alive]),
            "total_workers": len(self._workers),
            "affinities": {bid: w.pid for bid, w in self._affinity.items()},
        }

    # ------------------------------------------------------------------

    def _get_worker(self, method: str, params: dict, binary_id: str | None) -> _Worker:
        """Find the best worker for this request.

        Must be called under ``self._lock``. Honors binary_id affinity, prefers
        idle workers, spawns new workers up to ``max_workers``, and finally
        evicts the least-recently-active worker.

        Args:
            method: JSON-RPC method name.
            params: JSON-RPC parameters.
            binary_id: Affinity key; if a live worker owns this binary, return it.

        Returns:
            A live ``_Worker`` selected for the request.
        """
        # 1. Check affinity
        if binary_id and binary_id in self._affinity:
            w = self._affinity[binary_id]
            if w.alive:
                return w
            # Dead worker — remove affinity
            del self._affinity[binary_id]
            self._workers = [x for x in self._workers if x is not w]

        # 2. For open_binary, find an idle worker or spawn new
        # For other methods, the binary should already be opened (affinity should exist)
        # Use any alive worker as fallback
        idle_workers = [w for w in self._workers if w.alive and w.binary_id is None]
        if idle_workers:
            return idle_workers[0]

        # 3. Spawn new worker if under limit
        if len([w for w in self._workers if w.alive]) < self.max_workers:
            return self._spawn()

        # 4. At capacity — evict LRU
        alive = [w for w in self._workers if w.alive]
        alive.sort(key=lambda w: w.last_activity)
        victim = alive[0]
        # Close its binary gracefully
        try:
            victim.send("close_binary", {"binary_id": victim.binary_id, "save": False}, self._msg_id + 1000)
        except Exception:
            pass
        if victim.binary_id and victim.binary_id in self._affinity:
            del self._affinity[victim.binary_id]
        victim.binary_id = None
        return victim

    def _spawn(self) -> _Worker:
        """Spawn a new worker subprocess.

        Must be called under ``self._lock``.

        Returns:
            The newly spawned ``_Worker``.
        """
        env = {
            **os.environ,
            "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
            "IDA_HEADLESS_MCP_IDA_DIR": str(self.settings.ida_dir),
            "IDA_HEADLESS_MCP_CACHE_DIR": str(self.settings.cache_dir),
            "IDA_HEADLESS_MCP_PROJECT_DIR": str(self.settings.project_dir),
        }
        proc = subprocess.Popen(
            [sys.executable, "-m", "ida_headless_mcp.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        worker = _Worker(proc=proc, pid=proc.pid)

        # Start stdout reader thread
        def _read():
            for line in proc.stdout:
                worker._stdout_q.put(line.decode("utf-8", errors="replace").rstrip())
            worker._stdout_q.put(None)

        worker._reader_thread = threading.Thread(target=_read, daemon=True)
        worker._reader_thread.start()

        # Wait for ready signal
        try:
            line = worker._stdout_q.get(timeout=30)
            if line:
                msg = json.loads(line)
                if msg.get("method") == "worker/ready":
                    worker.pid = msg.get("params", {}).get("pid", proc.pid)
        except (queue.Empty, json.JSONDecodeError):
            pass

        self._workers.append(worker)
        return worker
