"""SMT prover interface — pipes QF_BV scripts to binbit.

The MCP server uses this to prove/disprove overflow conditions,
expression equivalences, and predicate opacity. binbit is a
purpose-built bitvector CDCL solver that's 10-100x faster than Z3
on typical symbex/vuln-proof workloads.

Usage:
    from ida_headless_mcp.smt_prover import solve_smtlib
    result = solve_smtlib("(declare-const x ...) (check-sat)")
    # result = {"result": "sat", "model": {"x": 42}, "time_ms": 4}
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

__all__ = ["solve_smtlib", "binbit_available"]

# Resolve binbit binary path — platform-appropriate extension
_BINBIT_NAME = "binbit.exe" if platform.system() == "Windows" else "binbit"
_BINBIT_PATH: str | None = os.environ.get(
    "IDA_HEADLESS_MCP_BINBIT_PATH",
    str(Path(__file__).parent.parent.parent / "tools" / _BINBIT_NAME),
)


def binbit_available() -> bool:
    """Check if the binbit binary exists and is executable."""
    if not _BINBIT_PATH:
        return False
    p = Path(_BINBIT_PATH)
    return p.exists() and p.is_file()


def solve_smtlib(
    script: str,
    *,
    timeout_ms: int = 5000,
) -> dict[str, Any]:
    """Run an SMT-LIB script through binbit and return the result.

    Args:
        script: Complete SMT-LIB 2.6 script text (QF_BV logic).
        timeout_ms: Maximum milliseconds before killing the solver.

    Returns:
        Dict with:
        - result: "sat" | "unsat" | "timeout" | "error"
        - model: dict of variable -> value (only on SAT with get-value)
        - time_ms: solver wall-clock time
        - raw_output: full solver output text
    """
    if not binbit_available():
        return {
            "result": "error",
            "model": {},
            "time_ms": 0,
            "raw_output": "binbit binary not found",
        }

    # Write script to temp file (binbit reads from file, not stdin)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".smt2", delete=False, encoding="utf-8",
    ) as f:
        f.write(script)
        tmp_path = f.name

    try:
        t0 = time.monotonic()
        proc = subprocess.run(
            [_BINBIT_PATH, "--smt", tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout_ms / 1000.0,
            stdin=subprocess.DEVNULL,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        output = proc.stdout.strip()
        lines = output.splitlines()

        # Parse result
        result = "error"
        if lines:
            first = lines[0].strip().lower()
            if first == "sat":
                result = "sat"
            elif first == "unsat":
                result = "unsat"
            elif first.startswith("unknown"):
                result = "timeout"

        # Parse model (get-value output)
        model: dict[str, int] = {}
        if result == "sat" and len(lines) > 1:
            model = _parse_model(lines[1:])

        return {
            "result": result,
            "model": model,
            "time_ms": elapsed_ms,
            "raw_output": output,
        }

    except subprocess.TimeoutExpired:
        return {
            "result": "timeout",
            "model": {},
            "time_ms": timeout_ms,
            "raw_output": "",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "result": "error",
            "model": {},
            "time_ms": 0,
            "raw_output": str(exc),
        }
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass  # Best-effort temp file cleanup; OS reaps on reboot if this fails


def _parse_model(lines: list[str]) -> dict[str, int]:
    """Parse binbit's get-value output into a name -> int dict.

    Format: ((name (_ bvN W))) or ((name #xHEX)) or ((name #bBIN))
    """
    model: dict[str, int] = {}
    text = " ".join(lines)

    # Match patterns like (name (_ bvN W))
    for m in re.finditer(r'\((\w+)\s+\(_ bv(\d+) \d+\)\)', text):
        model[m.group(1)] = int(m.group(2))

    # Match patterns like (name #xHEX)
    for m in re.finditer(r'\((\w+)\s+#x([0-9a-fA-F]+)\)', text):
        model[m.group(1)] = int(m.group(2), 16)

    # Match patterns like (name #bBIN)
    for m in re.finditer(r'\((\w+)\s+#b([01]+)\)', text):
        model[m.group(1)] = int(m.group(2), 2)

    return model
