"""Logical network topology: gateway + segments, and a bounded set of
device-pairs sampled for ping latency/loss.

A device-pair "link" is only meaningful when it stays bad -- one lost ping
or one slow reply is normal network jitter, not a faulty switch segment.
This module turns the raw samples :class:`pinoc.collectors.network_matrix.
NetworkMatrixCollector` writes into ``network_matrix_samples`` into:

* a *segment* view for the topology web page (gateway + segments derived
  from the fleet's device inventory, each with its member pairs and
  whether any of them is persistently degraded), and
* a single ``device_id -> segment name`` lookup
  (:meth:`NetworkTopology.degraded_segment_for`) that
  :mod:`pinoc.correlation` can factor in as one more shared-cause hint,
  alongside Wi-Fi SSID, gateway, and IP subnet.

Both the device-pair set and the segment set are always bounded: an
explicit config list is capped, and the auto-derived fallback groups by a
shared device tag and chains members pairwise (O(n) per segment) rather
than ever pairing every device with every other one.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger("pinoc.topology")

DEFAULT_MAX_PAIRS = 40
DEFAULT_LATENCY_WARNING_MS = 80.0
DEFAULT_LATENCY_CRITICAL_MS = 250.0
DEFAULT_LOSS_WARNING_PERCENT = 5.0
DEFAULT_PERSISTENCE_SAMPLES = 3
DEFAULT_INTERVAL_SECONDS = 60.0
DEFAULT_PING_COUNT = 3
DEFAULT_PING_TIMEOUT_SECONDS = 2.0


class TopologyConfigError(ValueError):
    """The ``network_topology`` configuration section is invalid."""


@dataclass(frozen=True)
class Segment:
    name: str
    devices: Tuple[str, ...]
    gateway: Optional[str] = None


@dataclass(frozen=True)
class TopologyConfig:
    enabled: bool
    gateway: Optional[str]
    segments: Tuple[Segment, ...]
    pairs: Tuple[Tuple[str, str], ...]
    latency_warning_ms: float
    latency_critical_ms: float
    loss_warning_percent: float
    persistence_samples: int
    interval_seconds: float
    ping_count: int
    ping_timeout_seconds: float

    def segment_for(self, device_id: str) -> Optional[str]:
        for segment in self.segments:
            if device_id in segment.devices:
                return segment.name
        return None


def _auto_segments(known_ids: Iterable[str], device_tags: Dict[str, Tuple[str, ...]],
                   gateway: Optional[str]) -> List[Segment]:
    """Group devices by a shared tag when no explicit segments are given.

    Bounded and deterministic: at most one segment per distinct tag value
    shared by two or more devices (sorted by tag name), plus a catch-all
    "lan" segment for any device that matched no shared tag. Never one
    segment per device, and never a full mesh.
    """
    known_ids = sorted(known_ids)
    by_tag: Dict[str, List[str]] = {}
    for device_id in known_ids:
        for tag in device_tags.get(device_id, ()):
            by_tag.setdefault(tag, []).append(device_id)
    segments = [Segment(name=tag, devices=tuple(members), gateway=gateway)
               for tag, members in sorted(by_tag.items()) if len(members) >= 2]
    grouped = {member for segment in segments for member in segment.devices}
    leftovers = tuple(sorted(set(known_ids) - grouped))
    if len(leftovers) >= 2:
        segments.append(Segment(name="lan", devices=leftovers, gateway=gateway))
    return segments


def _auto_pairs(segments: Iterable[Segment], max_pairs: int) -> List[Tuple[str, str]]:
    """A bounded, O(n) chain of consecutive devices per segment -- never
    the O(n^2) full mesh a naive "every device with every other" would be
    on a large fleet."""
    pairs: List[Tuple[str, str]] = []
    for segment in segments:
        members = segment.devices
        for i in range(len(members) - 1):
            if len(pairs) >= max_pairs:
                return pairs
            pairs.append((members[i], members[i + 1]))
    return pairs


def _bounded_number(section: Dict[str, Any], name: str, default: float, low: float, high: float) -> float:
    value = section.get(name, default)
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise TopologyConfigError(f"network_topology.thresholds.{name} must be a number") from None
    if isinstance(section.get(name), bool) or not low <= value <= high:
        raise TopologyConfigError(f"network_topology.thresholds.{name} must be between {low} and {high}")
    return value


def parse_topology_config(raw: Optional[Dict[str, Any]], known_ids: Iterable[str],
                          device_tags: Optional[Dict[str, Tuple[str, ...]]] = None) -> TopologyConfig:
    """Validate and normalize the ``network_topology`` config section.

    ``known_ids`` bounds and filters both the explicit and auto-derived
    segments/pairs against devices that actually exist -- a device removed
    or renamed since this was configured is skipped rather than failing
    the whole section. Raises :class:`TopologyConfigError` on a malformed
    shape or an out-of-range value (used for both config-save validation
    and runtime parsing, so both reject the same bad input).
    """
    raw = raw or {}
    if not isinstance(raw, dict):
        raise TopologyConfigError("network_topology must be an object")
    known_ids = set(known_ids)
    device_tags = device_tags or {}
    enabled = bool(raw.get("enabled", False))
    gateway = str(raw["gateway"]).strip() or None if raw.get("gateway") else None
    max_pairs = raw.get("max_pairs", DEFAULT_MAX_PAIRS)
    if isinstance(max_pairs, bool) or not isinstance(max_pairs, int) or not 1 <= max_pairs <= 500:
        raise TopologyConfigError("network_topology.max_pairs must be an integer between 1 and 500")

    configured_segments = raw.get("segments")
    if configured_segments is not None:
        if not isinstance(configured_segments, list):
            raise TopologyConfigError("network_topology.segments must be a list")
        segments: List[Segment] = []
        names = set()
        for index, entry in enumerate(configured_segments):
            if not isinstance(entry, dict) or not str(entry.get("name") or "").strip():
                raise TopologyConfigError(f"network_topology.segments[{index}] needs a name")
            name = str(entry["name"]).strip()
            if name in names:
                raise TopologyConfigError(f"network_topology.segments[{index}]: duplicate segment name {name!r}")
            names.add(name)
            members = entry.get("devices", [])
            if not isinstance(members, list) or any(not isinstance(m, str) for m in members):
                raise TopologyConfigError(f"network_topology.segments[{index}].devices must be a list of device ids")
            segments.append(Segment(name=name, devices=tuple(dict.fromkeys(m for m in members if m in known_ids)),
                                    gateway=(entry.get("gateway") or gateway)))
    else:
        segments = _auto_segments(known_ids, device_tags, gateway)

    configured_pairs = raw.get("pairs")
    if configured_pairs is not None:
        if not isinstance(configured_pairs, list):
            raise TopologyConfigError("network_topology.pairs must be a list")
        pairs: List[Tuple[str, str]] = []
        seen = set()
        for index, entry in enumerate(configured_pairs):
            if (not isinstance(entry, (list, tuple)) or len(entry) != 2
                    or not all(isinstance(x, str) for x in entry)):
                raise TopologyConfigError(
                    f"network_topology.pairs[{index}] must be a [source, target] pair of device ids")
            source, target = str(entry[0]), str(entry[1])
            if source == target or source not in known_ids or target not in known_ids:
                continue  # self-pair, or a device removed/renamed since this was configured
            key = tuple(sorted((source, target)))
            if key in seen:
                continue
            seen.add(key)
            pairs.append((source, target))
            if len(pairs) >= max_pairs:
                break
    else:
        pairs = _auto_pairs(segments, max_pairs)

    thresholds = raw.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise TopologyConfigError("network_topology.thresholds must be an object")
    latency_warning = _bounded_number(thresholds, "latency_warning_ms", DEFAULT_LATENCY_WARNING_MS, 1, 60000)
    latency_critical = _bounded_number(thresholds, "latency_critical_ms", DEFAULT_LATENCY_CRITICAL_MS,
                                       latency_warning, 60000)
    loss_warning = _bounded_number(thresholds, "loss_warning_percent", DEFAULT_LOSS_WARNING_PERCENT, 0, 100)
    persistence = thresholds.get("persistence_samples", DEFAULT_PERSISTENCE_SAMPLES)
    if isinstance(persistence, bool) or not isinstance(persistence, int) or not 1 <= persistence <= 20:
        raise TopologyConfigError("network_topology.thresholds.persistence_samples must be an integer between 1 and 20")

    interval = raw.get("interval_seconds", DEFAULT_INTERVAL_SECONDS)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 5 <= interval <= 86400:
        raise TopologyConfigError("network_topology.interval_seconds must be a number between 5 and 86400")
    ping_count = raw.get("ping_count", DEFAULT_PING_COUNT)
    if isinstance(ping_count, bool) or not isinstance(ping_count, int) or not 1 <= ping_count <= 10:
        raise TopologyConfigError("network_topology.ping_count must be an integer between 1 and 10")
    ping_timeout = raw.get("ping_timeout_seconds", DEFAULT_PING_TIMEOUT_SECONDS)
    if isinstance(ping_timeout, bool) or not isinstance(ping_timeout, (int, float)) or not 0.5 <= ping_timeout <= 30:
        raise TopologyConfigError("network_topology.ping_timeout_seconds must be a number between 0.5 and 30")

    return TopologyConfig(enabled=enabled, gateway=gateway, segments=tuple(segments), pairs=tuple(pairs),
                          latency_warning_ms=latency_warning, latency_critical_ms=latency_critical,
                          loss_warning_percent=loss_warning, persistence_samples=persistence,
                          interval_seconds=float(interval), ping_count=ping_count,
                          ping_timeout_seconds=float(ping_timeout))


def pair_samples(db: Any, source_id: str, target_id: str, limit: int) -> List[Dict[str, Any]]:
    if db is None or not getattr(db, "available", False):
        return []
    return db.rows(
        "SELECT * FROM network_matrix_samples WHERE source_id=? AND target_id=? ORDER BY id DESC LIMIT ?",
        (source_id, target_id, limit))


def _sample_breaches(sample: Dict[str, Any], config: TopologyConfig) -> bool:
    if not sample.get("ok"):
        return True
    loss = sample.get("loss_percent")
    if loss is not None and loss >= config.loss_warning_percent:
        return True
    latency = sample.get("latency_ms")
    return latency is not None and latency >= config.latency_warning_ms


def pair_degraded(samples: List[Dict[str, Any]], config: TopologyConfig) -> bool:
    """A pair is *persistently* degraded only when its last
    ``persistence_samples`` consecutive samples all breach a threshold --
    one lost ping or one slow reply must never flip a link red."""
    if len(samples) < config.persistence_samples:
        return False
    window = samples[:config.persistence_samples]
    return all(_sample_breaches(sample, config) for sample in window)


def pair_status(db: Any, source_id: str, target_id: str, config: TopologyConfig) -> Dict[str, Any]:
    samples = pair_samples(db, source_id, target_id, max(config.persistence_samples, 5))
    latest = samples[0] if samples else None
    degraded = pair_degraded(samples, config)
    critical = degraded and latest is not None and (
        not latest.get("ok") or (latest.get("latency_ms") or 0) >= config.latency_critical_ms)
    return {
        "source_id": source_id, "target_id": target_id, "latest": latest, "sample_count": len(samples),
        "degraded": degraded, "severity": "critical" if critical else ("warning" if degraded else "ok"),
    }


class NetworkTopology:
    """Read-side view over sampled pair history: segment status for the
    topology page, and a device -> degraded-segment lookup the correlation
    engine can use as shared-cause context.

    Sampling itself lives in
    :class:`pinoc.collectors.network_matrix.NetworkMatrixCollector`; this
    class only reads what that collector already wrote to
    ``network_matrix_samples``.
    """

    def __init__(self, db: Any, config: TopologyConfig) -> None:
        self.db = db
        self.config = config

    def pair_statuses(self) -> List[Dict[str, Any]]:
        return [pair_status(self.db, source, target, self.config) for source, target in self.config.pairs]

    def segment_statuses(self) -> List[Dict[str, Any]]:
        statuses = {(source, target): status
                    for (source, target), status in zip(self.config.pairs, self.pair_statuses())}
        result = []
        for segment in self.config.segments:
            members = set(segment.devices)
            owned = [status for (source, target), status in statuses.items()
                    if source in members and target in members]
            degraded = [status for status in owned if status["degraded"]]
            status = ("critical" if any(item["severity"] == "critical" for item in degraded)
                     else "degraded" if degraded else "ok")
            result.append({"name": segment.name, "devices": list(segment.devices), "gateway": segment.gateway,
                           "pairs": owned, "degraded_pairs": degraded, "status": status})
        return result

    def degraded_segment_for(self, device_id: str) -> Optional[str]:
        """The name of ``device_id``'s segment, but only when that segment
        currently has a persistently degraded pair -- ``None`` otherwise,
        including when the device isn't in any configured segment."""
        if self.db is None or not self.config.enabled:
            return None
        segment_name = self.config.segment_for(device_id)
        if segment_name is None:
            return None
        for status in self.segment_statuses():
            if status["name"] == segment_name:
                return segment_name if status["status"] != "ok" else None
        return None
