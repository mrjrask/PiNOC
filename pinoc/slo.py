"""SLOs and reliability scoring (enhancement #3).

Device health today is a binary instant snapshot (see :mod:`pinoc.health`)
plus alerts -- there is no view of whether a device, role, or tag is meeting
an availability target *over time*, and no early signal that reliability is
slowly degrading before something actually breaks.

This module lets operators define SLOs (a target percentage, a scope of
devices, and a rolling window) in config, computes rolling attainment and
error-budget burn from the ``health_samples`` history table (a lightweight
periodic point-in-time health sample HistoryManager writes on every poll --
see ``pinoc.history.HistoryManager._sample``, since nothing else in PiNOC
persists health at arbitrary past timestamps), and opens/resolves a real
alert through the *exact same* ``alerts`` table and lifecycle every device
alert uses when either burn-rate window crosses its threshold -- same
pattern as ``pinoc.self_monitoring.SelfMonitoringService``, down to the
synthetic device id an SLO alert is tagged onto (``pinoc-slo`` here, vs.
``pinoc-console`` there) so it reads at a glance as being about an SLO, not
a monitored device.

Burn-rate alerting uses the standard SRE two-window approach (a short
"fast burn" window and a longer "slow burn" window, both expressed as a
multiple of the allowed steady burn rate): both must cross their threshold
at once for an alert to open, which catches a sharp full outage quickly
without paging on a single short blip. This is a simplified, single-pair
version of Google's multi-window multi-burn-rate alerting (which typically
uses two *pairs* of windows for a page vs. a ticket) -- see the report's
MVP-scope notes.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from pinoc.database import utcnow

LOG = logging.getLogger("pinoc.slo")
UTC = timezone.utc

# Synthetic device_id SLO burn alerts are opened against -- never a real
# fleet device, so it can never collide with one (mirrors
# pinoc.self_monitoring.CONSOLE_DEVICE_ID).
SLO_DEVICE_ID = "pinoc-slo"
ALERT_TYPE = "slo_burn"

VALID_SCOPE_TYPES = {"device", "role", "tag"}

# Health states that count against an SLO's error budget. "maintenance" is
# excluded from both sides entirely (planned downtime should not count for
# or against reliability); "healthy"/"warning"/"degraded" all count as
# "good" for MVP purposes -- see the report's scope-cut notes for a
# per-metric (e.g. "degraded counts as bad") refinement this does not do.
BAD_HEALTH = {"critical", "offline"}

# The classic Google SRE workbook 30-day-window constants (2% of the monthly
# budget in 1h => 14.4x; 5% in 6h => 6x), used as defaults when a definition
# does not override them.
DEFAULT_BURN_RATE: Dict[str, float] = {
    "fast_window_minutes": 60, "fast_threshold": 14.4,
    "slow_window_minutes": 360, "slow_threshold": 6.0,
}

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class SLOConfigError(ValueError):
    pass


# -- config parsing/validation -----------------------------------------------

def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def parse_slo(raw: Any, index: int, known_device_ids: Iterable[str] = (),
              known_roles: Iterable[str] = (), known_tags: Iterable[str] = ()) -> Dict[str, Any]:
    """Parse and validate one ``slos.definitions[]`` entry into its
    normalized form. Raises :class:`SLOConfigError` (a ``ValueError``) on
    anything invalid; membership checks against ``known_*`` are skipped when
    the corresponding set is empty, so this doubles as a lightweight parser
    for callers (like :class:`SLOService`) that only have the already-
    validated config and no live roster handy.
    """
    if not isinstance(raw, dict):
        raise SLOConfigError(f"slos.definitions[{index}] must be an object")
    label = str(raw.get("id") or raw.get("name") or f"#{index + 1}")
    slo_id = str(raw.get("id") or "").strip()
    if not slo_id or not _ID_RE.fullmatch(slo_id):
        raise SLOConfigError(f"slo {label}: id is required and must be a simple identifier")
    name = str(raw.get("name") or slo_id).strip()
    scope = raw.get("scope")
    if not isinstance(scope, dict):
        raise SLOConfigError(f"slo {label}: scope must be an object")
    stype = str(scope.get("type") or "").strip().lower()
    if stype not in VALID_SCOPE_TYPES:
        raise SLOConfigError(f"slo {label}: scope.type must be one of {sorted(VALID_SCOPE_TYPES)}")
    svalue = str(scope.get("value") or "").strip()
    if not svalue:
        raise SLOConfigError(f"slo {label}: scope.value is required")
    known = {"device": set(known_device_ids), "role": set(known_roles), "tag": set(known_tags)}[stype]
    if known and svalue not in known:
        raise SLOConfigError(f"slo {label}: scope.value {svalue!r} does not match any known {stype}")
    target = _number(raw.get("target_percent"))
    if target is None or not 0 < target < 100:
        raise SLOConfigError(f"slo {label}: target_percent must be a number between 0 and 100 (exclusive)")
    window_days = raw.get("window_days", 30)
    if isinstance(window_days, bool) or not isinstance(window_days, int) or not 1 <= window_days <= 400:
        raise SLOConfigError(f"slo {label}: window_days must be an integer between 1 and 400")
    severity = str(raw.get("severity") or "critical")
    if severity not in ("info", "warning", "degraded", "critical"):
        raise SLOConfigError(f"slo {label}: severity must be info, warning, degraded, or critical")
    burn_raw = raw.get("burn_rate") or {}
    if not isinstance(burn_raw, dict):
        raise SLOConfigError(f"slo {label}: burn_rate must be an object")
    burn = dict(DEFAULT_BURN_RATE)
    for key in ("fast_window_minutes", "slow_window_minutes"):
        if key in burn_raw:
            value = _number(burn_raw[key])
            if value is None or not 1 <= value <= 44640:
                raise SLOConfigError(f"slo {label}: burn_rate.{key} must be minutes between 1 and 44640")
            burn[key] = value
    for key in ("fast_threshold", "slow_threshold"):
        if key in burn_raw:
            value = _number(burn_raw[key])
            if value is None or value <= 0:
                raise SLOConfigError(f"slo {label}: burn_rate.{key} must be a positive number")
            burn[key] = value
    if burn["fast_window_minutes"] >= burn["slow_window_minutes"]:
        raise SLOConfigError(f"slo {label}: burn_rate.fast_window_minutes must be smaller than slow_window_minutes")
    if burn["slow_window_minutes"] > window_days * 1440:
        raise SLOConfigError(f"slo {label}: burn_rate.slow_window_minutes cannot exceed the SLO window")
    return {"id": slo_id, "name": name, "scope": {"type": stype, "value": svalue},
            "target_percent": target, "window_days": window_days,
            "severity": severity, "burn_rate": burn}


def validate_slos(value: Dict[str, Any], known_device_ids: Iterable[str],
                   known_roles: Iterable[str] = (), known_tags: Iterable[str] = ()) -> None:
    """Validate the top-level ``slos`` config section (see
    ``pinoc.config_store.validate_config``). ``None``/absent is valid --
    the feature is a no-op until at least one definition exists."""
    section = value.get("slos")
    if section is None:
        return
    if not isinstance(section, dict):
        raise SLOConfigError("slos must be an object")
    if "enabled" in section and not isinstance(section["enabled"], bool):
        raise SLOConfigError("slos.enabled must be a boolean")
    interval = section.get("interval_seconds", 60)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 5 <= interval <= 86400:
        raise SLOConfigError("slos.interval_seconds must be a number between 5 and 86400")
    retention = section.get("sample_retention_days", 35)
    if isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 3650:
        raise SLOConfigError("slos.sample_retention_days must be an integer between 1 and 3650")
    definitions = section.get("definitions", [])
    if not isinstance(definitions, list):
        raise SLOConfigError("slos.definitions must be a list")
    if len(definitions) > 200:
        raise SLOConfigError("at most 200 SLO definitions are allowed")
    seen = set()
    for index, raw in enumerate(definitions):
        parsed = parse_slo(raw, index, known_device_ids, known_roles, known_tags)
        if parsed["id"] in seen:
            raise SLOConfigError(f"slo {parsed['id']}: duplicate id")
        seen.add(parsed["id"])


# -- scope resolution ---------------------------------------------------------

def resolve_scope_devices(scope: Dict[str, Any], devices: Sequence[Dict[str, Any]]) -> List[str]:
    """Resolve a ``{type, value}`` scope against a live device roster
    (``PiNOCState.devices()`` dicts, or anything with ``id``/``roles``/
    ``tags`` keys) to a list of device ids."""
    stype = scope.get("type")
    value = scope.get("value")
    if stype == "device":
        return [d["id"] for d in devices if d.get("id") == value]
    if stype == "role":
        return [d["id"] for d in devices if value in (d.get("roles") or [])]
    if stype == "tag":
        return [d["id"] for d in devices if value in (d.get("tags") or [])]
    return []


# -- attainment / burn-rate math ----------------------------------------------

def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _device_seconds(rows: Sequence[Dict[str, Any]], window_start: datetime, window_end: datetime,
                     cap_seconds: float = 1800.0) -> "tuple[float, float]":
    """Time-weighted good/bad seconds for one device's ``health_samples``
    rows (ascending, at most one sample before ``window_start`` for
    carry-forward) within ``[window_start, window_end]``.

    Each sample's health is assumed to hold until the next sample; a gap
    longer than ``cap_seconds`` (the collector/service was down, not just
    the device) is credited only up to the cap, on the conservative
    assumption that an unmeasured gap should not fully count either way --
    an MVP simplification noted in the report."""
    good = bad = 0.0
    count = len(rows)
    for index, row in enumerate(rows):
        ts = _parse_ts(row["timestamp"])
        nxt = _parse_ts(rows[index + 1]["timestamp"]) if index + 1 < count else window_end
        start = max(ts, window_start)
        end = min(nxt, window_end)
        if end <= start:
            continue
        duration = min((end - start).total_seconds(), cap_seconds)
        health = row.get("health") or "offline"
        if health == "maintenance":
            continue
        if health in BAD_HEALTH:
            bad += duration
        else:
            good += duration
    return good, bad


def compute_attainment(db: Any, device_ids: Sequence[str], window_start: datetime, window_end: datetime,
                        cap_seconds: float = 1800.0) -> Dict[str, Any]:
    """Pooled (summed across every device in scope) time-weighted
    attainment over ``[window_start, window_end]``, from the
    ``health_samples`` table. ``attainment_percent`` is ``None`` when no
    samples at all fall in range for any device in scope (still learning,
    or the scope resolved to no devices)."""
    total_good = total_bad = 0.0
    for device_id in device_ids:
        prior = db.rows(
            "SELECT timestamp,health FROM health_samples WHERE device_id=? AND timestamp<? "
            "ORDER BY timestamp DESC LIMIT 1",
            (device_id, window_start.isoformat()))
        rows = db.rows(
            "SELECT timestamp,health FROM health_samples WHERE device_id=? AND timestamp>=? AND timestamp<=? "
            "ORDER BY timestamp",
            (device_id, window_start.isoformat(), window_end.isoformat()))
        good, bad = _device_seconds([*prior, *rows], window_start, window_end, cap_seconds)
        total_good += good
        total_bad += bad
    total = total_good + total_bad
    attainment_percent = round((total_good / total) * 100, 4) if total > 0 else None
    return {"good_seconds": total_good, "bad_seconds": total_bad, "total_seconds": total,
            "attainment_percent": attainment_percent}


def burn_rate(attainment_percent: Optional[float], target_percent: float) -> Optional[float]:
    """How many multiples of the *sustainable* bad-event rate a window's
    actual bad rate represents (the SRE "burn rate"): 1.0 means "consuming
    the error budget exactly fast enough to exhaust it right at the end of
    the SLO window"; 14.4 for a 1h window against a 30-day/99.9% SLO is the
    classic "page now" threshold."""
    if attainment_percent is None:
        return None
    budget = max(1e-9, 100.0 - target_percent)
    bad_percent = max(0.0, 100.0 - attainment_percent)
    return bad_percent / budget


# -- service: periodic evaluation + alert lifecycle ---------------------------

class SLOService:
    """Ticks on an interval: evaluates every configured SLO's rolling
    attainment and fast/slow error-budget burn rate, then opens/resolves
    ``slo_burn`` alerts for whichever ones are burning budget too fast --
    through the same ``alerts`` table/lifecycle every device alert uses
    (see :mod:`pinoc.self_monitoring` for the identical pattern).

    ``db`` is the shared history ``Database``; ``state`` is the shared
    ``PiNOCState`` (its ``devices()`` resolves role/tag scopes against the
    *current* roster on every tick, so a device added/removed/re-tagged is
    picked up without a restart). Both -- and ``notifier`` -- are optional:
    a missing one simply means the service is idle or has fewer signals,
    never an error.
    """

    def __init__(self, db: Any = None, state: Any = None, config: Optional[Dict[str, Any]] = None,
                 notifier: Any = None, interval: Optional[int] = None) -> None:
        cfg = config or {}
        self.db = db
        self.state = state
        self.notifier = notifier
        self.enabled = bool(cfg.get("enabled", True))
        self.definitions: List[Dict[str, Any]] = []
        for index, raw in enumerate(cfg.get("definitions") or []):
            try:
                self.definitions.append(parse_slo(raw, index))
            except SLOConfigError:
                # Config is validated at save time (pinoc.config_store); a
                # bad entry here would mean the file was hand-edited after
                # the fact. Skip it rather than taking the whole service
                # down -- every other definition keeps working.
                LOG.warning("skipping invalid SLO definition #%d in loaded config", index)
        self.interval = max(5, int(interval if interval is not None else cfg.get("interval_seconds", 60)))
        self.retention_days = max(1, int(cfg.get("sample_retention_days", 35)))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-slo", daemon=True)

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        if self.enabled and self.definitions and self.db is not None:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                LOG.exception("SLO evaluation tick failed")
            self.stop_event.wait(self.interval)

    def _devices(self) -> List[Dict[str, Any]]:
        return self.state.devices() if self.state is not None else []

    # -- read side: dashboards/status pages read this directly -----------
    def evaluate_one(self, slo_def: Dict[str, Any], devices: Sequence[Dict[str, Any]],
                      now: Optional[datetime] = None) -> Dict[str, Any]:
        now = now or datetime.now(UTC)
        device_ids = resolve_scope_devices(slo_def["scope"], devices)
        window = compute_attainment(self.db, device_ids, now - timedelta(days=slo_def["window_days"]), now)
        burn = slo_def["burn_rate"]
        fast = compute_attainment(self.db, device_ids, now - timedelta(minutes=burn["fast_window_minutes"]), now)
        slow = compute_attainment(self.db, device_ids, now - timedelta(minutes=burn["slow_window_minutes"]), now)
        fast_burn = burn_rate(fast["attainment_percent"], slo_def["target_percent"])
        slow_burn = burn_rate(slow["attainment_percent"], slo_def["target_percent"])
        firing = (fast_burn is not None and slow_burn is not None
                  and fast_burn >= burn["fast_threshold"] and slow_burn >= burn["slow_threshold"])
        budget_total = max(1e-9, 100.0 - slo_def["target_percent"])
        attainment = window["attainment_percent"]
        budget_remaining_percent = None
        if attainment is not None:
            consumed = min(1.0, max(0.0, (100.0 - attainment) / budget_total))
            budget_remaining_percent = round((1.0 - consumed) * 100.0, 2)
        return {
            "id": slo_def["id"], "name": slo_def["name"], "scope": slo_def["scope"],
            "target_percent": slo_def["target_percent"], "window_days": slo_def["window_days"],
            "severity": slo_def["severity"], "device_count": len(device_ids), "device_ids": device_ids,
            "attainment_percent": attainment, "budget_remaining_percent": budget_remaining_percent,
            "fast_burn_rate": fast_burn, "fast_threshold": burn["fast_threshold"],
            "slow_burn_rate": slow_burn, "slow_threshold": burn["slow_threshold"],
            "firing": firing, "insufficient_data": attainment is None,
        }

    def snapshot(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        now = now or datetime.now(UTC)
        devices = self._devices()
        entries = []
        for slo_def in self.definitions:
            try:
                entries.append(self.evaluate_one(slo_def, devices, now))
            except Exception:  # noqa: BLE001 - one bad SLO must not break the rest
                LOG.exception("SLO evaluation failed for %s", slo_def.get("id"))
                entries.append({"id": slo_def["id"], "name": slo_def.get("name"), "error": "evaluation failed"})
        return {"generated_at": now.isoformat(), "slos": entries}

    def get_one(self, slo_id: str, now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        match = next((d for d in self.definitions if d["id"] == slo_id), None)
        if match is None:
            return None
        return self.evaluate_one(match, self._devices(), now)

    # -- write side: alert open/resolve, through the existing lifecycle --
    def tick(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        report = self.snapshot(now)
        if self.db is not None and self.db.available:
            try:
                self._reconcile(report)
            except Exception:
                LOG.exception("SLO alert reconcile failed")
        return report

    def _reconcile(self, report: Dict[str, Any]) -> None:
        active: List[tuple] = []  # (slo_id, severity, message)
        for entry in report["slos"]:
            if not entry.get("firing"):
                continue
            attainment = entry.get("attainment_percent")
            attainment_text = f"{attainment:.3f}%" if attainment is not None else "insufficient data"
            message = (
                f"{entry['name']} error budget is burning too fast: "
                f"{entry['fast_burn_rate']:.1f}x/{entry['fast_threshold']:.1f}x (fast window), "
                f"{entry['slow_burn_rate']:.1f}x/{entry['slow_threshold']:.1f}x (slow window) — "
                f"attainment {attainment_text} vs target {entry['target_percent']}% over {entry['window_days']}d"
            )
            active.append((entry["id"], entry["severity"], message))
        self._apply(active)

    def _apply(self, active: List[tuple]) -> None:
        stamp = utcnow()
        existing = {row["fingerprint"]: row for row in self.db.rows(
            "SELECT * FROM alerts WHERE device_id=? AND resolved_at IS NULL", (SLO_DEVICE_ID,))}
        seen = set()
        opened: List[Dict[str, Any]] = []
        resolved: List[Dict[str, Any]] = []
        for slo_id, severity, message in active:
            fingerprint = f"{SLO_DEVICE_ID}:{ALERT_TYPE}:{slo_id}"
            seen.add(fingerprint)
            if fingerprint in existing:
                row = existing[fingerprint]
                self.db.execute("UPDATE alerts SET last_seen_at=?,severity=?,message=? WHERE alert_id=?",
                                 (stamp, severity, message, row["alert_id"]))
            else:
                alert_id = self.db.execute(
                    "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,"
                    "last_seen_at,state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (SLO_DEVICE_ID, ALERT_TYPE, severity, message, fingerprint, stamp, stamp,
                     "active", json.dumps({"slo_id": slo_id})))
                opened.append({"alert_id": alert_id, "device_id": SLO_DEVICE_ID, "alert_type": ALERT_TYPE,
                               "severity": severity, "message": message})
        for fingerprint, row in existing.items():
            if fingerprint not in seen:
                self.db.execute("UPDATE alerts SET resolved_at=?,state='resolved' WHERE alert_id=?",
                                 (stamp, row["alert_id"]))
                resolved.append(row)
        if opened or resolved:
            self._notify(opened, resolved)
        if self.state is not None:
            self.state.set_alerts(self.db.rows(
                "SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY "
                "CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC"))

    def _notify(self, opened: List[Dict[str, Any]], resolved: List[Dict[str, Any]]) -> None:
        if self.notifier is None:
            return
        for row in opened:
            try:
                self.notifier.enqueue("open", row, "SLO error budget")
            except Exception:
                LOG.warning("SLO open notification failed", exc_info=True)
        for row in resolved:
            try:
                self.notifier.enqueue("resolve", row, "SLO error budget")
            except Exception:
                LOG.warning("SLO resolve notification failed", exc_info=True)
