"""Shared backend for PiNOC 2.0."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys


def _cryptography_available() -> bool:
    try:
        from cryptography.fernet import Fernet  # noqa: F401
    except ImportError:
        return False
    return True


def _ensure_runtime_dependencies() -> None:
    """Repair an existing virtualenv after requirements gain a dependency.

    PiNOC is commonly updated with ``git pull`` followed by a service restart.
    That updates the code but does not refresh the already-created virtualenv.
    If a core dependency required by the web application is missing or broken,
    sync the venv from requirements.txt before importing the rest of the package.
    """
    if _cryptography_available():
        return
    if os.environ.get("PINOC_DEPENDENCY_BOOTSTRAP") == "1":
        return

    repo_dir = Path(__file__).resolve().parent.parent
    requirements = repo_dir / "requirements.txt"
    if not requirements.is_file():
        return

    env = os.environ.copy()
    env["PINOC_DEPENDENCY_BOOTSTRAP"] = "1"
    print(
        "PiNOC: cryptography is missing or unusable; synchronizing Python dependencies...",
        file=sys.stderr,
        flush=True,
    )
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
            cwd=str(repo_dir),
            env=env,
            check=True,
        )
        importlib.invalidate_caches()
    except (OSError, subprocess.CalledProcessError) as exc:
        print(
            "PiNOC: dependency synchronization failed. Run "
            f"'{sys.executable} -m pip install -r {requirements}' manually. "
            f"Error: {exc}",
            file=sys.stderr,
            flush=True,
        )


_ensure_runtime_dependencies()

from .models import DeviceState
from .state import PiNOCState

__all__ = ["DeviceState", "PiNOCState"]
