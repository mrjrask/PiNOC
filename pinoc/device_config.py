"""Validated Milestone 2 fleet configuration with legacy translation."""
from __future__ import annotations

import json
import re
import socket
from dataclasses import replace
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

METHODS = {"local", "ssh"}
KNOWN_ROLES = {"file_server", "vpn_server", "adsb_receiver", "desk_display",
               "magicmirror", "pinoc", "hotspot", "general"}


class DeviceConfigError(ValueError):
    pass


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "device"


def _strings(value: Any, field_name: str, label: str, *, lowercase: bool = True) -> List[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise DeviceConfigError(f"device {label}: {field_name} must be a list of strings")
    normalized = (x.strip().lower() if lowercase else x.strip() for x in value)
    return list(dict.fromkeys(x for x in normalized if x))


@dataclass(frozen=True)
class DeviceConfig:
    id: str
    hostname: str
    friendly_name: str
    address: str
    collection_method: str
    roles: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    ssh_user: str = "pi"
    ssh_port: int = 22
    cockpit_enabled: bool = False
    cockpit_scheme: str = "https"
    cockpit_host: str = ""
    cockpit_port: int = 9090
    monitored_services: Tuple[str, ...] = ()
    critical_services: Tuple[str, ...] = ()
    manageable_services: Tuple[str, ...] = ()
    allowed_actions: Tuple[str, ...] = ()
    service_discovery: bool = False
    notes: str = ""
    important_paths: Tuple[str, ...] = ()
    maintenance: bool = False
    thresholds: Dict[str, float] = field(default_factory=dict)
    integrations: Dict[str, Any] = field(default_factory=dict)
    repositories: Tuple[Dict[str, Any], ...] = ()

    @property
    def cockpit_url(self) -> Optional[str]:
        if not self.cockpit_enabled:
            return None
        host = self.cockpit_host or self.address
        return f"{self.cockpit_scheme}://{host}:{self.cockpit_port}"


def parse_device(raw: Dict[str, Any], index: int) -> DeviceConfig:
    if not isinstance(raw, dict):
        raise DeviceConfigError(f"device #{index + 1}: entry must be an object")
    label = str(raw.get("id") or raw.get("hostname") or f"#{index + 1}")
    method = str(raw.get("collection_method", "ssh")).lower()
    if method not in METHODS:
        raise DeviceConfigError(f"device {label}: collection_method must be local or ssh")
    hostname = str(raw.get("hostname") or "").strip()
    address = str(raw.get("address") or hostname).strip()
    if method == "ssh" and not address:
        raise DeviceConfigError(f"device {label}: hostname or address is required")
    if method == "local" and not hostname:
        hostname = socket.gethostname()
        address = address or hostname
    device_id = str(raw.get("id") or _slug(hostname)).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", device_id):
        raise DeviceConfigError(f"device {label}: id contains invalid characters")
    roles = _strings(raw.get("roles", ["general"]), "roles", label)
    tags = _strings(raw.get("tags", []), "tags", label)
    monitored = _strings(raw.get("monitored_services", []), "monitored_services", label)
    critical = _strings(raw.get("critical_services", []), "critical_services", label)
    manageable = _strings(raw.get("manageable_services", []), "manageable_services", label)
    allowed_actions = _strings(raw.get("allowed_actions", []), "allowed_actions", label, lowercase=False)
    important_paths = _strings(raw.get("important_paths", []), "important_paths", label,
                               lowercase=False)
    if len(raw.get("monitored_services", [])) != len(set(raw.get("monitored_services", []))):
        raise DeviceConfigError(f"device {label}: monitored_services contains duplicates")
    monitored = list(dict.fromkeys(monitored + critical))
    try:
        ssh_port, cockpit_port = int(raw.get("ssh_port", 22)), int(raw.get("cockpit_port", 9090))
    except (TypeError, ValueError):
        raise DeviceConfigError(f"device {label}: ports must be integers") from None
    if not 1 <= ssh_port <= 65535:
        raise DeviceConfigError(f"device {label}: ssh_port must be between 1 and 65535")
    if not 1 <= cockpit_port <= 65535:
        raise DeviceConfigError(f"device {label}: cockpit_port must be between 1 and 65535")
    scheme = str(raw.get("cockpit_scheme", "https")).lower()
    if scheme not in ("http", "https"):
        raise DeviceConfigError(f"device {label}: cockpit_scheme must be http or https")
    thresholds = raw.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise DeviceConfigError(f"device {label}: thresholds must be an object")
    try:
        thresholds = {str(k): float(v) for k, v in thresholds.items()}
    except (TypeError, ValueError):
        raise DeviceConfigError(f"device {label}: threshold values must be numeric") from None
    integrations = raw.get("integrations", {})
    if not isinstance(integrations, dict):
        raise DeviceConfigError(f"device {label}: integrations must be an object")
    repositories = raw.get("repositories", [])
    if not isinstance(repositories, list) or any(not isinstance(x, dict) for x in repositories):
        raise DeviceConfigError(f"device {label}: repositories must be a list of objects")
    for name, value in integrations.items():
        if name not in {"adsb","desk_display","magicmirror","ics_modifier","pi_hotspot","wireguard","samba","raid","disk_health","packages","git"}:
            raise DeviceConfigError(f"device {label}: unknown integration {name}")
        if not isinstance(value, (bool, dict)):
            raise DeviceConfigError(f"device {label}: integration {name} must be a boolean or object")
    return DeviceConfig(device_id, hostname or address, str(raw.get("friendly_name") or hostname or address),
                        address, method, tuple(roles), tuple(tags), str(raw.get("ssh_user", "pi")),
                        ssh_port, bool(raw.get("cockpit_enabled", False)), scheme,
                        str(raw.get("cockpit_host", "")), cockpit_port, tuple(monitored), tuple(critical), tuple(manageable), tuple(allowed_actions),
                        bool(raw.get("service_discovery", False)), str(raw.get("notes", "")),
                        tuple(important_paths),
                        bool(raw.get("maintenance", False)), thresholds, integrations,
                        tuple(repositories))


def legacy_device(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not config.get("remote_host"):
        return None
    return {"id": config.get("remote_device_id", "cm5-file-server"),
            "hostname": config.get("remote_hostname", "cm5"),
            "friendly_name": config.get("remote_friendly_name", "CM5 File Server"),
            "address": config["remote_host"], "collection_method": "ssh",
            "ssh_user": config.get("remote_user", "pi"), "ssh_port": config.get("remote_ssh_port", 22),
            "roles": ["file_server"], "important_paths": [x["path"] for x in config.get("remote_paths", [])]}


def load_devices(config: Dict[str, Any], base_dir: Path) -> Tuple[List[DeviceConfig], List[str]]:
    source = config.get("devices", [])
    path = config.get("devices_file", "config/devices.json")
    file_path = base_dir / str(path)
    if file_path.exists():
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        source = payload.get("devices", [])
    if not isinstance(source, list):
        raise DeviceConfigError("devices must be a list")
    raw_devices = list(source)
    legacy = legacy_device(config)
    explicit_ids = {str(x.get("id")) for x in raw_devices if isinstance(x, dict) and x.get("id")}
    if legacy and str(legacy["id"]) not in explicit_ids:
        raw_devices.append(legacy)
    errors: List[str] = []
    devices: List[DeviceConfig] = []
    seen = set()
    for index, raw in enumerate(raw_devices):
        try:
            device = parse_device(raw, index)
            if device.id in seen:
                raise DeviceConfigError(f"device {device.id}: duplicate id")
            seen.add(device.id)
            devices.append(device)
        except DeviceConfigError as exc:
            errors.append(str(exc))
    global_thresholds = config.get("health_thresholds", {})
    if not isinstance(global_thresholds, dict):
        errors.append("health_thresholds must be an object")
    else:
        try:
            normalized = {str(k): float(v) for k, v in global_thresholds.items()}
            devices = [replace(d, thresholds={**normalized, **d.thresholds}) for d in devices]
        except (TypeError, ValueError):
            errors.append("health_thresholds values must be numeric")
    return devices, errors
