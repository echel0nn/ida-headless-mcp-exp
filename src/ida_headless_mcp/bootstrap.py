from __future__ import annotations

import importlib
import importlib.util
import os
import shutil
import site
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

from .config import Settings

__all__ = ["bootstrap_ida"]


def _run_python(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], text=True, capture_output=True)


def _ensure_ida_install(settings: Settings) -> None:
    required = [
        settings.ida_dir / "ida64.exe",
        settings.ida_dir / "idalib64.dll",
        settings.ida_dir / "idalib" / "python" / "setup.py",
        settings.ida_dir / "idalib" / "python" / "py-activate-idalib.py",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise FileNotFoundError("IDA install missing required files:\n" + "\n".join(missing))


def _ida_pkg_dir() -> Path:
    user_dir = Path(site.getusersitepackages()) / "ida"
    if user_dir.is_dir():
        return user_dir
    for site_path in site.getsitepackages():
        p = Path(site_path) / "ida"
        if p.is_dir():
            return p
    return user_dir


def _install_local_ida_package(settings: Settings) -> None:
    if importlib.util.find_spec("ida") is not None:
        return
    source_dir = settings.ida_dir / "idalib" / "python"
    with tempfile.TemporaryDirectory(prefix="ida-idalib-src-") as tmp:
        tmp_src = Path(tmp) / "python"
        shutil.copytree(source_dir, tmp_src)
        install = _run_python("-m", "pip", "install", str(tmp_src))
    if install.returncode != 0:
        raise RuntimeError("pip install for local ida package failed:\n" + install.stdout + "\n" + install.stderr)
    importlib.invalidate_caches()


def _activate_idalib(settings: Settings) -> None:
    activate = _run_python(
        str(settings.ida_dir / "idalib" / "python" / "py-activate-idalib.py"),
        "-d",
        str(settings.ida_dir),
    )
    if activate.returncode != 0:
        raise RuntimeError("py-activate-idalib.py failed:\n" + activate.stdout + "\n" + activate.stderr)

    bin_link = _ida_pkg_dir() / "bin"
    if bin_link.exists() or bin_link.is_symlink():
        return

    if os.name == "nt":
        mk = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(bin_link), str(settings.ida_dir)],
            text=True,
            capture_output=True,
        )
        if mk.returncode != 0:
            raise RuntimeError(
                "Failed to create ida/bin junction after activation:\n" + mk.stdout + "\n" + mk.stderr
            )
    if not (bin_link.exists() or bin_link.is_symlink()):
        raise RuntimeError(f"Activation completed but ida/bin link was not created at {bin_link}")


def bootstrap_ida(settings: Settings) -> ModuleType:
    """Ensure the local IDA idalib Python package is usable and import it.

    This function must run before any ``ida_*`` or ``idautils`` imports.

    Args:
        settings: Resolved settings, including the IDA install directory.

    Returns:
        The imported ``ida`` module.

    Raises:
        FileNotFoundError: If the IDA install is missing required files.
        RuntimeError: If pip install or activation steps fail.
    """
    # Fast path: if ida is already installed and activated, skip everything
    os.environ.setdefault("IDADIR", str(settings.ida_dir))
    bin_link = _ida_pkg_dir() / "bin"
    _spec = importlib.util.find_spec("ida")
    _bin_ok = bin_link.exists() or bin_link.is_symlink()
    import sys as _sys
    print(f'[bootstrap] find_spec(ida)={_spec is not None} bin_link={bin_link} exists={_bin_ok}', file=_sys.stderr, flush=True)
    if _spec is not None and _bin_ok:
        print(f'[bootstrap] FAST PATH', file=_sys.stderr, flush=True)
        return importlib.import_module("ida")

    print(f'[bootstrap] SLOW PATH - running pip/activation', file=_sys.stderr, flush=True)
    # Slow path: verify IDA install, pip install package, create junction
    _ensure_ida_install(settings)

    _install_local_ida_package(settings)
    _activate_idalib(settings)
    importlib.invalidate_caches()
    return importlib.import_module("ida")
