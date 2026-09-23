"""Validated Milestone 2 fleet configuration with legacy translation."""
from __future__ import annotations

import json
import re
import socket
from dataclasses import replace
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pinoc.actions import ALLOWLISTABLE_ACTIONS

METHODS = {"local", "ssh"}
KNOWN_ROLES = {"file_server", "vpn_server", "adsb_receiver", "desk_display",
               "magicmirror", "pinoc", "hotspot", "general"}
# A device's baseline of ports it is expected to listen on -- see
# pinoc.collectors.fleet._security_status(). "proto:port", e.g. "tcp:22".
_LISTENER_RE = re.compile(r"\A(tcp|udp):([0-9]{1,5})\Z")
MAX_EXPECTED_LISTENERS = 100
# Configuration drift detection (enhancement #6): a per-device expected-state
# spec collected/diffed by pinoc.collectors.fleet and repaired only through
# the allowlisted pinoc.actions "config_drift.*" actions. Bounded the same
# way expected_listeners/monitored_services are -- a handful of security-
# relevant units/files/options, not an arbitrary inventory.
MAX_DRIFT_UNITS = 20
MAX_DRIFT_FILES = 10
MAX_DRIFT_SSHD_OPTIONS = 25
# Unit names checked for drift are re-enabled by pinoc.actions'
# "config_drift.reenable_unit", which reuses actions.UNIT (".service" only,
# the same constraint every other unit-management action already has) --
# keep this in sync so a configured unit can actually be repaired.
_DRIFT_UNIT_RE = re.compile(r"[A-Za-z0-9_.@:-]{1,122}\.service")
_DRIFT_PATH_RE = re.compile(r"/[A-Za-z0-9/._@:-]{1,254}")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_SSHD_OPTION_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
_SSHD_VALUE_RE = re.compile(r"[^\r\n]{1,256}")


@dataclass(frozen=True)
class ConfigDriftSpec:
    """One device's expected-state baseline for drift detection.

    ``expected_files``/``expected_sshd_options`` map name -> expected value
    (sha256 digest / option value) rather than a list, mirroring
    ``thresholds``/``integrations`` elsewhere in :class:`DeviceConfig`.
    """
    expected_units: Tuple[str, ...] = ()
    expected_files: Dict[str, str] = field(default_factory=dict)
    expected_sshd_options: Dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not (self.expected_units or self.expected_files or self.expected_sshd_options)


class DeviceConfigError(ValueError):
    pass


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "device"


def _expected_listeners(value: Any, label: str) -> List[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise DeviceConfigError(f"device {label}: expected_listeners must be a list of 'tcp:PORT'/'udp:PORT' strings")
    if len(value) > MAX_EXPECTED_LISTENERS:
        raise DeviceConfigError(f"device {label}: at most {MAX_EXPECTED_LISTENERS} expected_listeners are allowed")
    result: List[str] = []
    for entry in value:
        normalized = entry.strip().lower()
        match = _LISTENER_RE.fullmatch(normalized)
        if not match or not 1 <= int(match.group(2)) <= 65535:
            raise DeviceConfigError(
                f"device {label}: expected_listeners entry {entry!r} must look like 'tcp:22' or 'udp:53' "
                "(port 1-65535)")
        if normalized not in result:
            result.append(normalized)
    return result


def _config_drift(value: Any, label: str) -> ConfigDriftSpec:
    if value in (None, {}):
        return ConfigDriftSpec()
    if not isinstance(value, dict):
        raise DeviceConfigError(f"device {label}: config_drift must be an object")
    units = value.get("expected_units", [])
    if not isinstance(units, list) or any(not isinstance(x, str) for x in units):
        raise DeviceConfigError(f"device {label}: config_drift.expected_units must be a list of strings")
    if len(units) > MAX_DRIFT_UNITS:
        raise DeviceConfigError(f"device {label}: at most {MAX_DRIFT_UNITS} config_drift.expected_units are allowed")
    normalized_units: List[str] = []
    for unit in units:
        unit = unit.strip()
        if not _DRIFT_UNIT_RE.fullmatch(unit):
            raise DeviceConfigError(
                f"device {label}: config_drift.expected_units entry {unit!r} must be a bare "
                "'<name>.service' unit name")
        if unit not in normalized_units:
            normalized_units.append(unit)
    files = value.get("expected_files", {})
    if not isinstance(files, dict):
        raise DeviceConfigError(f"device {label}: config_drift.expected_files must be an object of path -> sha256")
    if len(files) > MAX_DRIFT_FILES:
        raise DeviceConfigError(f"device {label}: at most {MAX_DRIFT_FILES} config_drift.expected_files are allowed")
    normalized_files: Dict[str, str] = {}
    for path, digest in files.items():
        if not isinstance(path, str) or ".." in path or not _DRIFT_PATH_RE.fullmatch(path):
            raise DeviceConfigError(f"device {label}: config_drift.expected_files path {path!r} is invalid")
        digest = str(digest).strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise DeviceConfigError(
                f"device {label}: config_drift.expected_files[{path!r}] must be a 64-hex-character sha256 digest")
        normalized_files[path] = digest
    options = value.get("expected_sshd_options", {})
    if not isinstance(options, dict):
        raise DeviceConfigError(f"device {label}: config_drift.expected_sshd_options must be an object")
    if len(options) > MAX_DRIFT_SSHD_OPTIONS:
        raise DeviceConfigError(
            f"device {label}: at most {MAX_DRIFT_SSHD_OPTIONS} config_drift.expected_sshd_options are allowed")
    normalized_options: Dict[str, str] = {}
    for option, expected in options.items():
        if not isinstance(option, str) or not _SSHD_OPTION_RE.fullmatch(option):
            raise DeviceConfigError(f"device {label}: config_drift.expected_sshd_options key {option!r} is invalid")
        expected = str(expected).strip()
        if not expected or not _SSHD_VALUE_RE.fullmatch(expected):
            raise DeviceConfigError(
                f"device {label}: config_drift.expected_sshd_options[{option!r}] must be a short single-line value")
        normalized_options[option.lower()] = expected
    return ConfigDriftSpec(tuple(normalized_units), normalized_files, normalized_options)


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
    # Optional baseline of "proto:port" entries this device is expected to
    # listen on (e.g. "tcp:22"). See pinoc.collectors.fleet for how a
    # listener outside this set (or a missing expected one) opens a
    # listener_change alert. Empty means "no baseline configured" -- the
    # collector still gathers the live listener inventory but never alerts
    # on it, matching how the rest of PiNOC treats unset optional config.
    expected_listeners: Tuple[str, ...] = ()
    # Optional expected-state baseline for configuration drift detection
    # (enhancement #6): enabled units, selected file hashes, selected sshd
    # options. Empty means "not configured" -- the collector never runs the
    # (bounded, low-frequency) drift checks for this device. See
    # pinoc.collectors.fleet.compute_config_drift and the "Configuration
    # drift detection" README section.
    config_drift: ConfigDriftSpec = field(default_factory=ConfigDriftSpec)

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
    unknown_actions = [a for a in allowed_actions if a not in ALLOWLISTABLE_ACTIONS]
    if unknown_actions:
        # ActionDispatcher.validate() compares allowed_actions entries
        # against exact-lowercase canonical action ids -- a typo (or any
        # other unrecognized string) here would otherwise pass validation
        # cleanly but can never match, silently disabling the intended
        # rescue action on this device with no warning at all.
        raise DeviceConfigError(
            f"device {label}: allowed_actions contains unknown action(s) {unknown_actions}; "
            f"must be exactly one of {sorted(ALLOWLISTABLE_ACTIONS)}")
    important_paths = _strings(raw.get("important_paths", []), "important_paths", label,
                               lowercase=False)
    expected_listeners = _expected_listeners(raw.get("expected_listeners"), label)
    config_drift = _config_drift(raw.get("config_drift"), label)
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
        if name not in {"adsb","desk_display","magicmirror","ics_modifier","pi_hotspot","wireguard","samba","raid","disk_health","packages","git","probe"}:
            raise DeviceConfigError(f"device {label}: unknown integration {name}")
        if not isinstance(value, (bool, dict)):
            raise DeviceConfigError(f"device {label}: integration {name} must be a boolean or object")
        if name == "probe":
            if isinstance(value, bool):
                raise DeviceConfigError(f"device {label}: probe must be an object with a checks list")
            from pinoc.integrations.probe import ProbeConfigError, validate_probes
            try:
                integrations[name] = validate_probes(label, value)
            except ProbeConfigError as exc:
                raise DeviceConfigError(str(exc)) from None
    return DeviceConfig(device_id, hostname or address, str(raw.get("friendly_name") or hostname or address),
                        address, method, tuple(roles), tuple(tags), str(raw.get("ssh_user", "pi")),
                        ssh_port, bool(raw.get("cockpit_enabled", False)), scheme,
                        str(raw.get("cockpit_host", "")), cockpit_port, tuple(monitored), tuple(critical), tuple(manageable), tuple(allowed_actions),
                        bool(raw.get("service_discovery", False)), str(raw.get("notes", "")),
                        tuple(important_paths),
                        bool(raw.get("maintenance", False)), thresholds, integrations,
                        tuple(repositories), tuple(expected_listeners), config_drift)


def legacy_device(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not config.get("remote_host"):
        return None
    return {"id": config.get("remote_device_id", "cm5-file-server"),
            "hostname": config.get("remote_hostname", "cm5"),
            "friendly_name": config.get("remote_friendly_name", "CM5 File Server"),
            "address": config["remote_host"], "collection_method": "ssh",
            "ssh_user": config.get("remote_user", "pi"), "ssh_port": config.get("remote_ssh_port", 22),
            "roles": ["file_server"], "important_paths": [x["path"] for x in config.get("remote_paths", [])]}


def validate_device_list(raw_devices: List[Any],
                         global_thresholds: Dict[str, Any]) -> Tuple[List[DeviceConfig], List[str]]:
    """Parse and validate a bare ``devices`` array against per-device global
    threshold defaults -- the same core loop :func:`load_devices` runs once it
    has resolved its raw device list from either ``config.json`` or the
    devices file, factored out so any other caller that already has a raw
    device list in hand (for example the onboarding wizard's confirm step in
    :func:`pinoc.config_store.save_devices`) validates through this one path
    too, rather than hand-rolling its own JSON checks.
    """
    if not isinstance(raw_devices, list):
        raise DeviceConfigError("devices must be a list")
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
    if not isinstance(global_thresholds, dict):
        errors.append("health_thresholds must be an object")
    else:
        try:
            normalized = {str(k): float(v) for k, v in global_thresholds.items()}
            devices = [replace(d, thresholds={**normalized, **d.thresholds}) for d in devices]
        except (TypeError, ValueError):
            errors.append("health_thresholds values must be numeric")
    return devices, errors


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
    return validate_device_list(raw_devices, config.get("health_thresholds", {}))
