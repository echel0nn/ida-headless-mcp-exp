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
    return subprocess.run([sys.executable, *args], text=True, capture_output=True, stdin=subprocess.DEVNULL)


def _ensure_ida_install(settings: Settings) -> None:
    if sys.platform == "darwin":
        required = [
            settings.ida_dir / "idat",
            settings.ida_dir / "idalib" / "python" / "idapro-0.0.7-py3-none-any.whl",
            settings.ida_dir / "idalib" / "python" / "py-activate-idalib.py",
        ]
    elif sys.platform == "linux":
        required = [
            settings.ida_dir / "idat64",
            settings.ida_dir / "idalib64.so",
            settings.ida_dir / "idalib" / "python" / "setup.py",
            settings.ida_dir / "idalib" / "python" / "py-activate-idalib.py",
        ]
    else:
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

    # IDA 9.3+ on macOS ships as a .whl file rather than a source package
    wheels = list(source_dir.glob("*.whl"))
    if wheels:
        install = _run_python("-m", "pip", "install", str(wheels[0]))
        if install.returncode != 0:
            raise RuntimeError("pip install for ida wheel failed:\n" + install.stdout + "\n" + install.stderr)
        importlib.invalidate_caches()
        return

    # Source package (setup.py) path — used by IDA 9.0 on Windows/Linux
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

    # macOS: idapro uses ~/.idapro/ida-config.json (created by py-activate-idalib.py)
    if _is_macos():
        config = Path.home() / ".idapro" / "ida-config.json"
        if not config.exists():
            raise RuntimeError(
                f"Activation completed but idapro config was not created at {config}"
            )
        return

    # Windows / Linux: create junction/symlink so import ida can find the IDA dir
    bin_link = _ida_pkg_dir() / "bin"
    if bin_link.exists() or bin_link.is_symlink():
        return

    if os.name == "nt":
        mk = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(bin_link), str(settings.ida_dir)],
            text=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )
        if mk.returncode != 0:
            raise RuntimeError(
                "Failed to create ida/bin junction after activation:\n" + mk.stdout + "\n" + mk.stderr
            )
    else:
        try:
            bin_link.parent.mkdir(parents=True, exist_ok=True)
            bin_link.symlink_to(settings.ida_dir, target_is_directory=True)
        except OSError as exc:
            raise RuntimeError(
                f"Failed to create ida/bin symlink after activation at {bin_link}: {exc}"
            ) from exc
    if not (bin_link.exists() or bin_link.is_symlink()):
        raise RuntimeError(f"Activation completed but ida/bin link was not created at {bin_link}")


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _find_ida_module_spec() -> object:
    """Find the ida module spec, handling macOS package name."""
    spec = importlib.util.find_spec("ida")
    if spec is not None:
        return spec
    # macOS IDA 9.3 ships as idapro package
    if _is_macos():
        spec = importlib.util.find_spec("idapro")
    return spec


def _import_ida_module() -> ModuleType:
    """Import and return the IDA Python module, handling macOS naming."""
    if _is_macos():
        import idapro
        return idapro
    return importlib.import_module("ida")


def _activation_ok(settings: Settings) -> bool:
    """Check whether IDA activation is complete for the current platform."""
    if _is_macos():
        # macOS: idapro stores its config in ~/.idapro/ida-config.json
        config = Path.home() / ".idapro" / "ida-config.json"
        return config.exists()
    # Windows/Linux: check for ida/bin junction/symlink
    bin_link = _ida_pkg_dir() / "bin"
    return bin_link.exists() or bin_link.is_symlink()


def bootstrap_ida(settings: Settings) -> ModuleType:
    """Ensure the local IDA idalib Python package is usable and import it.

    This function must run before any ``ida_*`` or ``idautils`` imports.

    Args:
        settings: Resolved settings, including the IDA install directory.

    Returns:
        The imported ``ida`` (or ``idapro`` on macOS) module.

    Raises:
        FileNotFoundError: If the IDA install is missing required files.
        RuntimeError: If pip install or activation steps fail.
    """
    # Fast path: if ida is already installed and activated, skip everything
    os.environ.setdefault("IDADIR", str(settings.ida_dir))
    pkg = "idapro" if _is_macos() else "ida"
    _spec = _find_ida_module_spec()
    _activated = _activation_ok(settings)
    import sys as _sys
    print(f'[bootstrap] find_spec({pkg})={_spec is not None} activated={_activated}', file=_sys.stderr, flush=True)
    if _spec is not None and _activated:
        print(f'[bootstrap] FAST PATH', file=_sys.stderr, flush=True)
        return _import_ida_module()

    print(f'[bootstrap] SLOW PATH - running pip/activation', file=_sys.stderr, flush=True)
    # Slow path: verify IDA install, pip install package, create activation
    _ensure_ida_install(settings)

    _install_local_ida_package(settings)
    _activate_idalib(settings)
    importlib.invalidate_caches()
    return _import_ida_module()
