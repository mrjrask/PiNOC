"""Thread-safe current-state cache shared by every frontend."""
from __future__ import annotations

import copy
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from .models import DeviceState


class PiNOCState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._devices: Dict[str, DeviceState] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._legacy_snapshot: Any = None
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._last_collection: Optional[str] = None
        self._publish_hooks: List[Any] = []

    def add_publish_hook(self, hook: Any) -> None:
        """Register a fast, failure-isolated observer of published snapshots."""
        with self._lock:
            self._publish_hooks.append(hook)

    def publish(
        self,
        devices: Iterable[DeviceState],
        legacy_snapshot: Any = None,
        replace: bool = False,
    ) -> None:
        incoming = list(devices)
        with self._lock:
            incoming_ids: Set[str] = {device.id for device in incoming}
            if replace:
                for device_id in list(self._devices):
                    if device_id not in incoming_ids:
                        del self._devices[device_id]
            for device in incoming:
                existing = self._devices.get(device.id)
                if existing and not device.first_seen:
                    device.first_seen = existing.first_seen
                if existing and not device.last_seen:
                    device.last_seen = existing.last_seen
                if not device.first_seen:
                    device.first_seen = device.last_seen
                self._devices[device.id] = copy.deepcopy(device)
            if legacy_snapshot is not None:
                self._legacy_snapshot = legacy_snapshot
            self._last_collection = datetime.now(timezone.utc).isoformat()
            published = [copy.deepcopy(d.to_dict()) for d in incoming]
        for hook in tuple(self._publish_hooks):
            try:
                hook(published)
            except Exception:
                # Persistence and other observers must never break live state.
                continue

    def set_alerts(self, alerts: Iterable[Dict[str, Any]]) -> None:
        with self._lock:
            self._alerts = copy.deepcopy(list(alerts))
            ranks = {"healthy": 0, "warning": 1, "degraded": 2, "critical": 3, "offline": 4}
            by_device: Dict[str, List[Dict[str, Any]]] = {}
            for alert in self._alerts:
                by_device.setdefault(str(alert.get("device_id", "")), []).append(alert)
            for device_id, device in self._devices.items():
                active = by_device.get(device_id, [])
                device.alerts = copy.deepcopy(active)
                highest = max((str(a.get("severity", "info")) for a in active),
                              key=lambda value: ranks.get(value, 0), default="healthy")
                if ranks.get(highest, 0) > ranks.get(device.health, 0):
                    device.health = highest
                    device.health_reasons.append(f"{highest} active alert")

    def legacy_snapshot(self) -> Any:
        with self._lock:
            return copy.deepcopy(self._legacy_snapshot)

    def devices(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(d.to_dict()) for d in self._devices.values()]

    def device(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            device = self._devices.get(device_id)
            return copy.deepcopy(device.to_dict()) if device else None

    def alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._alerts)

    def summary(self) -> Dict[str, Any]:
        devices = self.devices()
        counts = {name: 0 for name in ("healthy", "warning", "degraded", "critical", "offline", "maintenance")}
        for device in devices:
            counts[device.get("health", "offline")] = counts.get(device.get("health", "offline"), 0) + 1
        failed_services = sum(
            1 for device in devices for service in device.get("services", [])
            if service.get("state") in ("failed", "inactive", "stopped")
        )
        return {
            "devices": len(devices), "online": sum(bool(d.get("online")) for d in devices),
            **counts, "warnings": counts["warning"] + counts["degraded"],
            "failed_services": failed_services,
            "updates_available": sum(
                int(d.get("applications", {}).get("updates_available", 0) or 0) for d in devices
            ),
            "database": "not_configured", "started_at": self._started_at,
            "last_collection": self._last_collection,
        }
