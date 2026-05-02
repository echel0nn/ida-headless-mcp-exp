from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "diff"
OUT_DIR_DEFAULT = ROOT / ".local-fixtures"


def find_clang() -> str:
    for candidate in ("clang", "clang.exe"):
        path = shutil.which(candidate)
        if path:
            return path
    raise FileNotFoundError("clang not found on PATH")


def build_one(clang: str, src: Path, out_exe: Path) -> None:
    cmd = [clang, "-O0", "-g0", "-fno-inline", str(src), "-o", str(out_exe)]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"clang failed for {src.name}:\n{proc.stdout}\n{proc.stderr}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build local diff fixture executables")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR_DEFAULT)
    args = parser.parse_args()

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    clang = find_clang()

    vuln_exe = out_dir / "vuln.exe"
    patched_exe = out_dir / "patched.exe"
    build_one(clang, FIXTURE_DIR / "vuln.c", vuln_exe)
    build_one(clang, FIXTURE_DIR / "patched.c", patched_exe)

    print(vuln_exe)
    print(patched_exe)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
