"""Central fleet health classification."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

DEFAULTS = {"cpu_warning": 70, "memory_warning": 80, "temperature_warning": 70,
            "temperature_critical": 80, "disk_warning": 80, "disk_critical": 95,
            "stale_seconds": 30, "offline_seconds": 120}


def _age(timestamp: str | None, now: datetime) -> float:
    if not timestamp:
        return float("inf")
    return (now - datetime.fromisoformat(timestamp.replace("Z", "+00:00"))).total_seconds()


def evaluate(device: Dict[str, Any], thresholds: Dict[str, float] | None = None,
             now: datetime | None = None) -> Tuple[str, list[str], bool]:
    t = {**DEFAULTS, **(thresholds or {})}; now = now or datetime.now(timezone.utc)
    age = _age(device.get("last_successful_collection") or device.get("last_seen"), now)
    if age > t["offline_seconds"]:
        return "offline", ["telemetry offline"], False
    if device.get("maintenance"):
        return "maintenance", ["maintenance mode"], False
    stale = age > t["stale_seconds"]
    warnings, critical = [], []
    cpu, mem, hw = device.get("cpu", {}), device.get("memory", {}), device.get("hardware", {})
    if (cpu.get("utilization_percent") or 0) > t["cpu_warning"]: warnings.append("high CPU utilization")
    if (mem.get("percent") or 0) > t["memory_warning"]: warnings.append("high memory utilization")
    temp = cpu.get("temperature_c")
    if temp is not None and temp > t["temperature_critical"]: critical.append("critical CPU temperature")
    elif temp is not None and temp > t["temperature_warning"]: warnings.append("high CPU temperature")
    important_paths = device.get("important_paths", [])
    for disk in device.get("storage", []):
        pct = disk.get("percent")
        mount_point = disk.get("mount_point") or disk.get("path")
        important = bool(mount_point) and any(
            path == mount_point or path.startswith(mount_point.rstrip("/") + "/")
            for path in important_paths
        )
        if disk.get("read_only") and important: critical.append(f"{mount_point} is read-only")
        if pct is not None and pct > t["disk_critical"]: critical.append("filesystem nearly full")
        elif pct is not None and pct > t["disk_warning"]: warnings.append("filesystem usage high")
    if hw.get("undervoltage_now") or hw.get("throttled_now"): critical.append("current Pi power/throttle condition")
    elif hw.get("undervoltage_occurred") or hw.get("throttled_occurred"): warnings.append("historical Pi power/throttle condition")
    critical_names = set(device.get("critical_services", []))
    for service in device.get("services", []):
        if service.get("state") not in ("running", "activating"):
            (critical if service.get("name") in critical_names or service.get("critical") else warnings).append(
                f"service {service.get('name')} is {service.get('state', 'unknown')}")
    raid = device.get("applications", {}).get("raid", {}).get("status")
    if raid in ("DEGRADED", "INACTIVE", "MISSING"): critical.append("RAID degraded")
    if critical: return "critical", critical + warnings, stale
    if stale: return "degraded", ["telemetry stale"] + warnings, True
    if len(warnings) >= 2: return "degraded", warnings, False
    if warnings: return "warning", warnings, False
    return "healthy", [], False
