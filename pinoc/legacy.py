"""Normalize the existing display snapshot without duplicating collection."""
from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Iterable

from .models import DeviceState


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_snapshot(snapshot: Any, config: Dict[str, Any]) -> Iterable[DeviceState]:
    local = snapshot.local
    mem_percent = round(local.memory_used * 100 / local.memory_total, 1) if local.memory_total else None
    local_device = DeviceState(
        id=str(config.get("local_device_id") or f"local:{socket.gethostname()}"),
        hostname=local.hostname, friendly_name=str(config.get("local_friendly_name", "PiNOC Console")),
        roles=["pinoc", "desk_display"], ip=local.wlan_ip, local_hostname=f"{local.hostname}.local",
        architecture=platform.machine(), os=platform.system(), kernel=platform.release(),
        uptime_seconds=local.uptime_seconds, last_seen=_now(), online=True, health="healthy",
        cpu={"temperature_c": local.temperature_c, "load_1m": local.load_1m},
        memory={"total": local.memory_total, "used": local.memory_used,
                "available": max(0, local.memory_total-local.memory_used), "percent": mem_percent},
        network={"interface": "wlan0", "ip": local.wlan_ip, "wifi_ssid": local.wifi_ssid},
        applications={"wireguard": vars(snapshot.vpn), "inside_sensor": vars(snapshot.sensor)},
    )
    remote = snapshot.remote
    raid_critical = remote.raid_status in ("DEGRADED", "INACTIVE", "MISSING")
    remote_device = DeviceState(
        id=str(config.get("remote_device_id", "cm5-file-server")), hostname=str(config.get("remote_host", "cm5")),
        friendly_name=str(config.get("remote_friendly_name", "CM5 File Server")), roles=["file_server"],
        ip=str(config.get("remote_host", "")), uptime_seconds=remote.uptime_seconds,
        last_seen=_now() if remote.online else None, online=remote.online,
        health="critical" if raid_critical else ("healthy" if remote.online else "offline"),
        cpu={"temperature_c": remote.temperature_c, "load_1m": remote.load_1m},
        storage=[{"name": d.name, "path": d.path, "total": d.total, "used": d.used,
                  "available": d.available, "percent": d.percent, "error": d.error} for d in remote.disks],
        applications={"raid": {"status": remote.raid_status, "detail": remote.raid_detail},
                      "samba": {"sessions": remote.smb_sessions, "users": remote.smb_users,
                                  "error": remote.smb_error}}, error=remote.error,
    )
    yield local_device
    yield remote_device
    for temp in snapshot.temp_devices:
        yield DeviceState(id=temp.device_id, hostname=temp.hostname, friendly_name=temp.hostname,
                          roles=["temperature_sensor"], ip=temp.ip, last_seen=_now(), online=True,
                          health="healthy", cpu={"temperature_c": temp.celsius})
