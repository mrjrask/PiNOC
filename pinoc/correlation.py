"""Alert correlation: group open alerts that likely share one root cause.

A single shared cause -- a Wi-Fi access point dropping, a switch reboot, a
power blip -- can open near-identical alerts on many devices at once. This
module clusters those open alerts by *shared context* (same trigger class,
plus the same Wi-Fi SSID, gateway/WAN interface, or IP subnet) within a
rolling time window, so the UI can show one explainable cluster card
instead of a wall of near-duplicate rows, and so notifications fire once
per cluster instead of once per member.

This is a presentation/notification layer only: it is conservative by
design and never merges, mutates, or suppresses the underlying alerts.
Every alert keeps its own row and lifecycle in the ``alerts`` table; a
cluster is just a label -- ``alerts.cluster_id`` -- attached to alerts that
appear to share a cause, plus a small summary row in ``alert_clusters``.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

LOG = logging.getLogger("pinoc.correlation")
UTC = timezone.utc
_SEVERITY_RANK = {"info": 0, "warning": 1, "degraded": 2, "critical": 3}

# Coarse buckets so alerts caused by the same underlying event correlate
# even when the exact alert_type differs (e.g. a warning-level temperature
# alert on one device and a critical one on another, both driven by the
# same failed fan). Alert types not listed fall back to their own name as
# a single-member class, so grouping stays conservative by default.
_TRIGGER_CLASSES = {
    "device_offline": "connectivity",
    "high_temperature": "temperature", "critical_temperature": "temperature",
    "high_cpu": "cpu",
    "high_memory": "memory",
    "high_disk_usage": "storage", "critical_disk_usage": "storage",
    "filesystem_read_only": "storage", "media_io_errors": "storage", "raid_degraded": "storage",
    "undervoltage_now": "power", "throttled_now": "power",
    "frequency_capped_now": "power", "soft_temp_limit_now": "power",
    "service_failed": "service", "critical_service_failed": "service",
    "anomaly": "anomaly",
}

# Priority order for shared context: a persistently degraded network-
# topology segment (see pinoc.topology) is measured evidence of a shared
# cause, so it outranks the topology *hints* below it -- SSID is the most
# specific of those (a single access point), then the gateway/WAN
# interface a device routes through, then a coarse /24 IP subnet as a
# fallback for wired devices or when Wi-Fi details are unavailable. Each
# alert is grouped on the single highest-priority hint it has, so it never
# lands in more than one cluster.
CONTEXT_PRIORITY = ("segment", "ssid", "gateway", "ip_prefix")


def trigger_class(alert_type: str) -> str:
    return _TRIGGER_CLASSES.get(alert_type, alert_type)


def context_hints(device: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Shared-cause hints for one device, from its own network state."""
    device = device or {}
    network = device.get("network") or {}
    hints: Dict[str, str] = {}
    ssid = network.get("ssid")
    if ssid:
        hints["ssid"] = str(ssid)
    gateway = network.get("default_gateway")
    if gateway:
        hints["gateway"] = str(gateway)
    ip = str(network.get("ip") or device.get("ip") or "")
    parts = ip.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        hints["ip_prefix"] = ".".join(parts[:3]) + ".0/24"
    return hints


def describe_context(context_key: str, context_value: str, label: Optional[str] = None) -> str:
    """Human-readable explanation of what a cluster's members have in common."""
    if context_key == "segment":
        return f'network segment "{context_value}" (persistent latency/loss)'
    if context_key == "ssid":
        return f'Wi-Fi SSID "{context_value}"'
    if context_key == "gateway":
        return f"gateway {context_value}" + (f" ({label})" if label else "")
    if context_key == "ip_prefix":
        return f"subnet {context_value}"
    return f"{context_key} {context_value}"


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def _parse(stamp: str) -> datetime:
    value = datetime.fromisoformat(stamp)
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _within(now: datetime, other_stamp: str, window_seconds: float) -> bool:
    try:
        return abs((now - _parse(other_stamp)).total_seconds()) <= window_seconds
    except (TypeError, ValueError):
        return False


class CorrelationOutcome:
    """Result of one correlation pass: what to skip notifying individually,
    and any cluster-level notifications that should fire instead."""

    def __init__(self) -> None:
        self.absorbed_open: Set[int] = set()
        self.absorbed_resolve: Set[int] = set()
        self.events: List[Dict[str, Any]] = []


class CorrelationEngine:
    """Conservative, explainable clustering of open alerts by shared cause.

    Grouping only: alerts are never merged, deduplicated, or suppressed --
    each keeps its own row and independent lifecycle in ``alerts``.
    Clustering only changes how alerts are *presented* (one card instead of
    many rows) and *notified* (one notification per cluster transition,
    not one per member).
    """

    def __init__(self, db: Any, config: Optional[Dict[str, Any]] = None, topology: Any = None):
        self.db = db
        config = config or {}
        self.enabled = bool(config.get("enabled", True))
        self.window_seconds = float(config.get("window_seconds", 300))
        self.min_members = max(2, int(config.get("min_members", 2)))
        # Optional pinoc.topology.NetworkTopology: when set, its
        # degraded_segment_for(device_id) is folded into this device's
        # context hints (see _hints()) as shared-cause evidence, ahead of
        # the topology *hints* below it in CONTEXT_PRIORITY. None (the
        # default) preserves every existing behavior exactly.
        self.topology = topology

    def reconcile(
        self,
        opened_ids: Iterable[int],
        resolved: List[Dict[str, Any]],
        device_context: Dict[str, Dict[str, Any]],
        stamp: str,
    ) -> CorrelationOutcome:
        outcome = CorrelationOutcome()
        if not self.enabled:
            return outcome
        opened_ids = set(opened_ids)
        now = _parse(stamp)

        self._resolve_finished_clusters(stamp, outcome)

        unclustered = self.db.rows("SELECT * FROM alerts WHERE resolved_at IS NULL AND cluster_id IS NULL")
        leftovers: List[Dict[str, Any]] = []
        for row in unclustered:
            hints = self._hints(row["device_id"], device_context)
            cls = trigger_class(row["alert_type"])
            cluster = self._attach_to_existing(cls, hints, row, now, stamp)
            if cluster is not None:
                if row["alert_id"] in opened_ids:
                    outcome.absorbed_open.add(row["alert_id"])
            else:
                leftovers.append(row)

        self._form_new_clusters(leftovers, device_context, now, stamp, opened_ids, outcome)

        for alert in resolved:
            if alert.get("cluster_id"):
                outcome.absorbed_resolve.add(alert["alert_id"])
        return outcome

    # -- internals --------------------------------------------------------
    def _resolve_finished_clusters(self, stamp: str, outcome: CorrelationOutcome) -> None:
        for cluster in self.db.rows("SELECT * FROM alert_clusters WHERE resolved_at IS NULL"):
            open_count = self.db.scalar(
                "SELECT COUNT(*) FROM alerts WHERE cluster_id=? AND resolved_at IS NULL", (cluster["cluster_id"],))
            if not open_count:
                self.db.execute(
                    "UPDATE alert_clusters SET resolved_at=?,last_seen_at=? WHERE cluster_id=?",
                    (stamp, stamp, cluster["cluster_id"]))
                if cluster.get("notified_open"):
                    outcome.events.append({"type": "resolve", "cluster": {**cluster, "resolved_at": stamp}})

    def _open_cluster_for(self, cls: str, key: str, value: str) -> Optional[Dict[str, Any]]:
        rows = self.db.rows(
            "SELECT * FROM alert_clusters WHERE resolved_at IS NULL AND trigger_class=? AND context_key=? AND context_value=?",
            (cls, key, value))
        return rows[0] if rows else None

    def _hints(self, device_id: str, device_context: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
        hints = context_hints(device_context.get(device_id))
        if self.topology is not None:
            try:
                segment = self.topology.degraded_segment_for(device_id)
            except Exception:  # topology lookup must never break correlation
                LOG.warning("network topology context lookup failed for %s", device_id, exc_info=True)
                segment = None
            if segment:
                hints = {"segment": segment, **hints}
        return hints

    def _attach_to_existing(self, cls: str, hints: Dict[str, str], row: Dict[str, Any],
                             now: datetime, stamp: str) -> Optional[Dict[str, Any]]:
        for key in CONTEXT_PRIORITY:
            value = hints.get(key)
            if not value:
                continue
            cluster = self._open_cluster_for(cls, key, value)
            if cluster and _within(now, cluster["last_seen_at"], self.window_seconds):
                self.db.execute("UPDATE alerts SET cluster_id=? WHERE alert_id=?", (cluster["cluster_id"], row["alert_id"]))
                severity = _max_severity(cluster["severity"], row["severity"])
                self.db.execute(
                    "UPDATE alert_clusters SET last_seen_at=?,severity=? WHERE cluster_id=?",
                    (stamp, severity, cluster["cluster_id"]))
                return cluster
        return None

    def _form_new_clusters(self, leftovers: List[Dict[str, Any]], device_context: Dict[str, Dict[str, Any]],
                            now: datetime, stamp: str, opened_ids: Set[int], outcome: CorrelationOutcome) -> None:
        grouped: Dict[tuple, List[Dict[str, Any]]] = {}
        for row in leftovers:
            if abs((now - _parse(row["opened_at"])).total_seconds()) > self.window_seconds:
                continue  # too stale to seed a brand-new cluster
            hints = self._hints(row["device_id"], device_context)
            cls = trigger_class(row["alert_type"])
            for key in CONTEXT_PRIORITY:
                value = hints.get(key)
                if value:
                    grouped.setdefault((cls, key, value), []).append(row)
                    break
        for (cls, key, value), members in grouped.items():
            distinct_devices = {member["device_id"] for member in members}
            if len(distinct_devices) < self.min_members:
                continue
            label = self._gateway_label(value) if key == "gateway" else None
            cluster = self._create_cluster(cls, key, value, members, stamp, label)
            outcome.events.append({"type": "open", "cluster": cluster})
            for member in members:
                if member["alert_id"] in opened_ids:
                    outcome.absorbed_open.add(member["alert_id"])

    def _create_cluster(self, cls: str, key: str, value: str, members: List[Dict[str, Any]],
                         stamp: str, label: Optional[str]) -> Dict[str, Any]:
        severity = "info"
        for member in members:
            severity = _max_severity(severity, member["severity"])
        opened_at = min(member["opened_at"] for member in members)
        context_json = json.dumps({"label": label} if label else {})
        cluster_id = self.db.execute(
            "INSERT INTO alert_clusters(trigger_class,context_key,context_value,context_json,severity,opened_at,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            (cls, key, value, context_json, severity, opened_at, stamp))
        for member in members:
            self.db.execute("UPDATE alerts SET cluster_id=? WHERE alert_id=?", (cluster_id, member["alert_id"]))
        rows = self.db.rows("SELECT * FROM alert_clusters WHERE cluster_id=?", (cluster_id,))
        return rows[0]

    def _gateway_label(self, ip: str) -> Optional[str]:
        """Best-effort LAN-inventory hint: a friendlier name for a gateway IP,
        when something has populated ``network_inventory`` for it. Absent
        that data the cluster still forms and explains itself by IP alone."""
        try:
            rows = self.db.rows("SELECT hostname,vendor FROM network_inventory WHERE ip=?", (ip,))
        except Exception:  # pragma: no cover - inventory is optional
            return None
        if not rows:
            return None
        return rows[0].get("hostname") or rows[0].get("vendor")
