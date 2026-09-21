"""PiNOC virtual-environment dependency self-healing.

Python imports ``sitecustomize`` automatically during interpreter startup when
it is present on ``sys.path``.  PiNOC's systemd service starts Python with the
repository as its working directory, so this gives existing installations a
safe upgrade path when a newly-added runtime dependency is present in
requirements.txt but the local virtual environment has not yet been refreshed.

This intentionally repairs only missing core runtime imports.  It does not run
pip on every startup.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys

_BOOTSTRAP_ENV = "PINOC_DEPENDENCY_BOOTSTRAP"
_REQUIRED_IMPORTS = ("cryptography",)


def _missing_imports() -> list[str]:
    return [name for name in _REQUIRED_IMPORTS if importlib.util.find_spec(name) is None]


def _bootstrap_dependencies() -> None:
    if os.environ.get(_BOOTSTRAP_ENV) == "1":
        return

    missing = _missing_imports()
    if not missing:
        return

    repo_dir = Path(__file__).resolve().parent
    requirements = repo_dir / "requirements.txt"
    if not requirements.is_file():
        return

    env = os.environ.copy()
    env[_BOOTSTRAP_ENV] = "1"
    print(
        "PiNOC: missing Python dependencies "
        f"({', '.join(missing)}); synchronizing virtual environment...",
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
    except (OSError, subprocess.CalledProcessError) as exc:
        print(
            "PiNOC: dependency synchronization failed; run "
            f"'{sys.executable} -m pip install -r {requirements}' manually. "
            f"Error: {exc}",
            file=sys.stderr,
            flush=True,
        )


_bootstrap_dependencies()
