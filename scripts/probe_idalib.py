from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import venv
from pathlib import Path

IDA_DIR_DEFAULT = Path(r"C:/Program Files/IDA Professional 9.0")
VENV_DIR_DEFAULT = Path(".probe-venv")


def _print(msg: str) -> None:
    print(f"[probe] {msg}")


def ensure_ida_install(ida_dir: Path) -> None:
    required = [
        ida_dir / "ida64.exe",
        ida_dir / "idat64.exe",
        ida_dir / "idalib64.dll",
        ida_dir / "idalib" / "python" / "setup.py",
        ida_dir / "idalib" / "python" / "py-activate-idalib.py",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise FileNotFoundError("IDA install missing required files:\n" + "\n".join(missing))


def ensure_venv(venv_dir: Path) -> Path:
    py = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if py.exists():
        _print(f"Using existing venv at {venv_dir}")
        return py
    _print(f"Creating venv at {venv_dir}")
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)
    if not py.exists():
        raise RuntimeError(f"Venv created but python not found at {py}")
    return py


def run(python_exe: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [str(python_exe), *args]
    return subprocess.run(cmd, text=True, capture_output=True, env=env)


def ensure_ida_package(python_exe: Path, ida_dir: Path) -> None:
    check = run(python_exe, "-c", "import importlib.util; print(importlib.util.find_spec('ida') is not None)")
    if check.returncode == 0 and check.stdout.strip() == "True":
        _print("Python package 'ida' already installed in probe venv")
        return
    _print("Installing local idalib python package into probe venv")
    source_dir = ida_dir / "idalib" / "python"
    with tempfile.TemporaryDirectory(prefix="ida-idalib-src-") as tmp:
        tmp_src = Path(tmp) / "python"
        shutil.copytree(source_dir, tmp_src)
        install = run(python_exe, "-m", "pip", "install", str(tmp_src))
    if install.returncode != 0:
        raise RuntimeError("pip install failed:\n" + install.stdout + "\n" + install.stderr)


def activate_idalib(python_exe: Path, ida_dir: Path, venv_dir: Path) -> None:
    _print("Activating idalib package (creating ida/bin link)")
    activate = run(
        python_exe,
        str(ida_dir / "idalib" / "python" / "py-activate-idalib.py"),
        "-d",
        str(ida_dir),
    )
    if activate.returncode != 0:
        raise RuntimeError("py-activate-idalib.py failed:\n" + activate.stdout + "\n" + activate.stderr)
    bin_link = venv_dir / "Lib" / "site-packages" / "ida" / "bin"
    if bin_link.exists() or bin_link.is_symlink():
        return
    if os.name == "nt":
        _print("Python activation did not create ida/bin; creating Windows junction fallback")
        mk = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(bin_link), str(ida_dir)],
            text=True,
            capture_output=True,
        )
        if mk.returncode != 0:
            raise RuntimeError(
                "Failed to create ida/bin junction after activation:\n" + mk.stdout + "\n" + mk.stderr
            )
    if not (bin_link.exists() or bin_link.is_symlink()):
        raise RuntimeError(f"Activation completed but ida/bin link was not created at {bin_link}")


def run_probe_payload(python_exe: Path, ida_dir: Path, binary: Path) -> subprocess.CompletedProcess[str]:
    script = textwrap.dedent(
        f"""
        from __future__ import annotations
        import json
        import os
        from pathlib import Path

        os.environ['IDADIR'] = r'{ida_dir}'

        import ida  # must be first IDA import
        import ida_auto
        import ida_funcs
        import ida_hexrays
        import ida_idaapi
        import ida_kernwin
        import ida_name
        import ida_nalt
        import ida_segment
        import idautils
        import idc

        results: dict[str, object] = {{}}
        results['idadir'] = os.environ.get('IDADIR')
        results['ida_module_file'] = getattr(ida, '__file__', None)
        results['sdk_version'] = getattr(ida_idaapi, 'IDA_SDK_VERSION', None)
        if hasattr(ida_kernwin, 'get_kernel_version'):
            results['kernel_version'] = ida_kernwin.get_kernel_version()
        else:
            results['kernel_version'] = None

        rc = ida.open_database(r'{binary}', True)
        results['open_database_rc'] = rc

        ida_auto.auto_wait()

        results['root_filename'] = ida_nalt.get_root_filename()
        results['function_count'] = ida_funcs.get_func_qty()
        results['segment_count'] = ida_segment.get_segm_qty()
        results['entry_qty'] = idc.get_entry_qty()

        functions = list(idautils.Functions())
        results['first_function_ea'] = f"0x{{functions[0]:x}}" if functions else None
        results['first_function_name'] = ida_name.get_ea_name(functions[0]) if functions else None

        decompiler_ready = ida_hexrays.init_hexrays_plugin()
        results['hexrays_ready'] = bool(decompiler_ready)
        if decompiler_ready and functions:
            try:
                cfunc = ida_hexrays.decompile(functions[0])
                pseudocode = str(cfunc)
                results['decompile_ok'] = True
                results['decompile_preview'] = "\\n".join(pseudocode.splitlines()[:15])
                results['decompile_line_count'] = len(pseudocode.splitlines())
            except Exception as exc:
                results['decompile_ok'] = False
                results['decompile_error'] = repr(exc)
        else:
            results['decompile_ok'] = False
            results['decompile_error'] = 'Hex-Rays unavailable or no functions found'

        ida.close_database(False)
        print(json.dumps(results, indent=2))
        """
    )
    return run(python_exe, "-c", script, env={**os.environ, "IDADIR": str(ida_dir)})


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe IDA 9.0 idalib viability")
    parser.add_argument("--ida-dir", type=Path, default=IDA_DIR_DEFAULT)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--venv-dir", type=Path, default=VENV_DIR_DEFAULT)
    args = parser.parse_args()

    ida_dir = args.ida_dir.resolve()
    binary = args.binary.resolve()
    venv_dir = args.venv_dir.resolve()

    _print(f"IDA dir: {ida_dir}")
    _print(f"Test binary: {binary}")

    ensure_ida_install(ida_dir)
    if not binary.exists():
        raise FileNotFoundError(f"Test binary not found: {binary}")

    python_exe = ensure_venv(venv_dir)
    _print(f"Probe python: {python_exe}")

    ensure_ida_package(python_exe, ida_dir)
    activate_idalib(python_exe, ida_dir, venv_dir)

    _print("Running probe payload")
    result = run_probe_payload(python_exe, ida_dir, binary)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
