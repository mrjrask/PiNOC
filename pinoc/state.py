"""Thread-safe current-state cache shared by every frontend."""
from __future__ import annotations

import copy
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from .models import DeviceState


class PiNOCState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._devices: Dict[str, DeviceState] = {}
        self._alerts: list[Dict[str, Any]] = []
        self._legacy_snapshot: Any = None
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._last_collection: Optional[str] = None

    def publish(self, devices: Iterable[DeviceState], legacy_snapshot: Any = None) -> None:
        with self._lock:
            for device in devices:
                existing = self._devices.get(device.id)
                if existing and not device.first_seen:
                    device.first_seen = existing.first_seen
                if not device.first_seen:
                    device.first_seen = device.last_seen
                self._devices[device.id] = copy.deepcopy(device)
            if legacy_snapshot is not None:
                self._legacy_snapshot = legacy_snapshot
            self._last_collection = datetime.now(timezone.utc).isoformat()

    def set_alerts(self, alerts: Iterable[Dict[str, Any]]) -> None:
        with self._lock:
            self._alerts = copy.deepcopy(list(alerts))

    def legacy_snapshot(self) -> Any:
        with self._lock:
            return copy.deepcopy(self._legacy_snapshot)

    def devices(self) -> list[Dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(d.to_dict()) for d in self._devices.values()]

    def device(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            device = self._devices.get(device_id)
            return copy.deepcopy(device.to_dict()) if device else None

    def alerts(self) -> list[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._alerts)

    def summary(self) -> Dict[str, Any]:
        devices = self.devices()
        counts = {name: 0 for name in ("healthy", "warning", "degraded", "critical", "offline")}
        for device in devices:
            counts[device.get("health", "offline")] = counts.get(device.get("health", "offline"), 0) + 1
        failed_services = sum(
            1 for device in devices for service in device.get("services", [])
            if service.get("state") in ("failed", "inactive")
        )
        return {
            "devices": len(devices), "online": sum(bool(d.get("online")) for d in devices),
            **counts, "warnings": counts["warning"] + counts["degraded"],
            "failed_services": failed_services,
            "updates_available": sum(int(d.get("applications", {}).get("updates_available", 0) or 0) for d in devices),
            "database": "not_configured", "started_at": self._started_at,
            "last_collection": self._last_collection,
        }
