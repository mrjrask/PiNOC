"""Validate PiNOC configuration: ``python3 -m pinoc.validate_config``."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from .config_store import validate_config
from .device_config import DeviceConfigError, load_devices


def main() -> int:
    root = Path.cwd()
    try:
        config = json.loads((root / "config.json").read_text(encoding="utf-8"))
        # Apply the same full validation the web settings editor and the
        # service use, so the preflight check catches invalid values in every
        # group (polling, authentication, security, playbooks) and not only
        # device entries; otherwise a bad value can pass here and still crash
        # startup later.
        validate_config(config, root)
        devices, errors = load_devices(config, root)
    except (OSError, json.JSONDecodeError, ValueError, DeviceConfigError) as exc:
        print(f"Configuration invalid: {exc}", file=sys.stderr); return 1
    if errors:
        print("Configuration contains invalid device entries:", file=sys.stderr)
        for error in errors: print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"Configuration valid: {len(devices)} fleet device(s) loaded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
