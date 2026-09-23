"""Scheduled fleet health reports (enhancement #5).

Export exists on demand (``/api/export/<kind>``, ``/api/backup/export``), but
nothing produces a recurring state-of-the-fleet document, so operators only
learn about slow trends -- filling disks, accumulating warnings, drifting
patch levels -- when they remember to open the console.

A *report definition* (the ``reports.definitions[]`` config section, see
:func:`validate_reports`) binds a firing schedule, a scope (whole fleet, a
role, or a tag), a set of content sections, an output format, and an
audience channel. Firing reuses :mod:`pinoc.schedules`'s cron/alias/one-shot
spec parsing (:func:`pinoc.schedules.next_after`) directly -- this module
does not implement a second scheduler -- and delivery reuses
:class:`pinoc.notifications.NotificationService`'s exact ntfy/smtp/webhook
channel implementations through its :meth:`~pinoc.notifications.NotificationService.send_direct`
method, so there is no second delivery mechanism either.

Each firing renders the chosen sections from data every other feature
already computes -- uptime/attainment from ``health_samples`` (the same
table :mod:`pinoc.slo` reads), the open-alert summary from ``alerts``,
per-mount capacity forecasts from :func:`pinoc.history.storage_forecast`,
storage-media health from the live device snapshot (the same signal
:meth:`pinoc.history.HistoryManager._alerts` opens ``media_io_errors``
alerts from), and patch status from the live device snapshot's package
metadata plus the most recent :mod:`pinoc.rollout` run touching each
device -- into HTML or CSV, stores the rendered edition (content + metadata)
in ``report_editions``, and delivers a short plain-text summary (open-alert
count, devices with pending updates, mounts filling up, ...) through the
configured channel; the full edition is archived and viewable/downloadable
from the Reports page rather than pushed whole through a channel that only
speaks plain text/JSON (see the report's MVP-scope notes: no PDF rendering
and no HTML e-mail body -- a printable HTML edition, opened from the
archive, covers the same "hand this to someone" need the same way
:mod:`pinoc.incidents`'s printable view does without a PDF dependency).

Like :class:`pinoc.slo.SLOService` and
:class:`pinoc.self_monitoring.SelfMonitoringService`, this is a poll-loop
("tick") service that needs no :class:`pinoc.actions.ActionDispatcher`, so
it is built the same way they are (in-line in ``create_app``) rather than
threaded through ``create_app``'s constructor kwargs.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from pinoc.database import utcnow
from pinoc.schedules import next_after, validate_spec
from pinoc.slo import compute_attainment

LOG = logging.getLogger("pinoc.reports")
UTC = timezone.utc

VALID_SCOPE_TYPES = ("fleet", "role", "tag")
VALID_SECTIONS = ("uptime", "alerts", "capacity", "storage_media", "patch_status")
VALID_FORMATS = ("html", "csv")

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class ReportConfigError(ValueError):
    pass


def now_utc() -> datetime:
    return datetime.now(UTC)


# -- config parsing/validation ------------------------------------------------

def parse_report(raw: Any, index: int, known_roles: Iterable[str] = (), known_tags: Iterable[str] = (),
                  known_channel_ids: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Parse and validate one ``reports.definitions[]`` entry. Raises
    :class:`ReportConfigError` on anything invalid; membership checks
    against ``known_*`` are skipped when the corresponding set is empty
    (mirrors :func:`pinoc.slo.parse_slo`)."""
    if not isinstance(raw, dict):
        raise ReportConfigError(f"reports.definitions[{index}] must be an object")
    label = str(raw.get("id") or raw.get("name") or f"#{index + 1}")
    report_id = str(raw.get("id") or "").strip()
    if not report_id or not _ID_RE.fullmatch(report_id):
        raise ReportConfigError(f"report {label}: id is required and must be a simple identifier")
    name = str(raw.get("name") or report_id).strip()
    spec = str(raw.get("spec") or "").strip()
    if not spec:
        raise ReportConfigError(f"report {label}: spec is required")
    tz = str(raw.get("timezone") or "UTC")
    try:
        validate_spec(spec, tz)
    except ValueError as exc:
        raise ReportConfigError(f"report {label}: {exc}") from None
    scope = raw.get("scope")
    if not isinstance(scope, dict):
        raise ReportConfigError(f"report {label}: scope must be an object")
    stype = str(scope.get("type") or "").strip().lower()
    if stype not in VALID_SCOPE_TYPES:
        raise ReportConfigError(f"report {label}: scope.type must be one of {list(VALID_SCOPE_TYPES)}")
    svalue = str(scope.get("value") or "").strip()
    if stype != "fleet":
        if not svalue:
            raise ReportConfigError(f"report {label}: scope.value is required for scope.type={stype}")
        known = {"role": set(known_roles), "tag": set(known_tags)}[stype]
        if known and svalue not in known:
            raise ReportConfigError(f"report {label}: scope.value {svalue!r} does not match any known {stype}")
    channel_id = str(raw.get("channel_id") or "").strip()
    if not channel_id:
        raise ReportConfigError(f"report {label}: channel_id is required")
    # Unlike known_roles/known_tags (deliberately skipped when empty -- see
    # pinoc.slo.parse_slo -- for a caller with no live roster handy), a
    # provided-but-empty known_channel_ids is not "no info available": it
    # means notifications.channels really is empty, and any channel_id is
    # therefore wrong. Only an omitted (None) known_channel_ids skips the
    # check, matching how ReportService re-parses already-validated config.
    if known_channel_ids is not None and channel_id not in set(known_channel_ids):
        raise ReportConfigError(
            f"report {label}: channel_id {channel_id!r} does not match any configured notification channel")
    sections = raw.get("sections", list(VALID_SECTIONS))
    if not isinstance(sections, list) or not sections:
        raise ReportConfigError(f"report {label}: sections must be a non-empty list")
    for section in sections:
        if section not in VALID_SECTIONS:
            raise ReportConfigError(f"report {label}: unknown section {section!r}; must be one of {list(VALID_SECTIONS)}")
    fmt = str(raw.get("format") or "html").lower()
    if fmt not in VALID_FORMATS:
        raise ReportConfigError(f"report {label}: format must be one of {list(VALID_FORMATS)}")
    window_days = raw.get("window_days", 7)
    if isinstance(window_days, bool) or not isinstance(window_days, int) or not 1 <= window_days <= 90:
        raise ReportConfigError(f"report {label}: window_days must be an integer between 1 and 90")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ReportConfigError(f"report {label}: enabled must be a boolean")
    return {"id": report_id, "name": name, "spec": spec, "timezone": tz,
            "scope": {"type": stype, "value": svalue or None}, "channel_id": channel_id,
            "sections": list(dict.fromkeys(sections)), "format": fmt, "window_days": window_days,
            "enabled": enabled}


def validate_reports(value: Dict[str, Any], known_roles: Iterable[str] = (), known_tags: Iterable[str] = (),
                      known_channel_ids: Optional[Iterable[str]] = None) -> None:
    """Validate the top-level ``reports`` config section (see
    ``pinoc.config_store.validate_config``). ``None``/absent is valid --
    the feature is a no-op until at least one definition exists."""
    section = value.get("reports")
    if section is None:
        return
    if not isinstance(section, dict):
        raise ReportConfigError("reports must be an object")
    if "enabled" in section and not isinstance(section["enabled"], bool):
        raise ReportConfigError("reports.enabled must be a boolean")
    interval = section.get("interval_seconds", 60)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 5 <= interval <= 86400:
        raise ReportConfigError("reports.interval_seconds must be a number between 5 and 86400")
    retention = section.get("edition_retention", 90)
    if isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 3650:
        raise ReportConfigError("reports.edition_retention must be an integer between 1 and 3650")
    definitions = section.get("definitions", [])
    if not isinstance(definitions, list):
        raise ReportConfigError("reports.definitions must be a list")
    if len(definitions) > 200:
        raise ReportConfigError("at most 200 report definitions are allowed")
    seen = set()
    for index, raw in enumerate(definitions):
        parsed = parse_report(raw, index, known_roles, known_tags, known_channel_ids)
        if parsed["id"] in seen:
            raise ReportConfigError(f"report {parsed['id']}: duplicate id")
        seen.add(parsed["id"])


# -- scope resolution ----------------------------------------------------------

def resolve_scope_devices(scope: Dict[str, Any], devices: Sequence[Dict[str, Any]]) -> List[str]:
    """Resolve a ``{type, value}`` scope (``fleet``/``role``/``tag``) against
    a live device roster to a list of device ids, sorted for determinism."""
    stype = scope.get("type")
    value = scope.get("value")
    if stype == "fleet":
        matched = [d["id"] for d in devices if d.get("id")]
    elif stype == "role":
        matched = [d["id"] for d in devices if value in (d.get("roles") or [])]
    elif stype == "tag":
        matched = [d["id"] for d in devices if value in (d.get("tags") or [])]
    else:
        matched = []
    return sorted(matched)


# -- content sections (pure, independently testable) --------------------------

def _device_label(devices_by_id: Dict[str, Dict[str, Any]], device_id: str) -> str:
    device = devices_by_id.get(device_id, {})
    return device.get("friendly_name") or device.get("hostname") or device_id


def uptime_section(db: Any, device_ids: Sequence[str], devices_by_id: Dict[str, Dict[str, Any]],
                    window_days: int, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Per-device and pooled attainment over the report window, from the
    same ``health_samples`` table/math :mod:`pinoc.slo` uses -- reused, not
    reimplemented, via :func:`pinoc.slo.compute_attainment`."""
    now = now or now_utc()
    window_start = now - timedelta(days=window_days)
    rows = []
    for device_id in device_ids:
        attainment = (compute_attainment(db, [device_id], window_start, now)
                      if db is not None else {"attainment_percent": None})
        rows.append({
            "device_id": device_id, "name": _device_label(devices_by_id, device_id),
            "online": bool(devices_by_id.get(device_id, {}).get("online")),
            "attainment_percent": attainment.get("attainment_percent"),
        })
    fleet = (compute_attainment(db, list(device_ids), window_start, now)
             if db is not None and device_ids else {"attainment_percent": None})
    return {"window_days": window_days, "fleet_attainment_percent": fleet.get("attainment_percent"),
            "devices": rows}


def alerts_section(db: Any, device_ids: Sequence[str], window_days: int,
                    now: Optional[datetime] = None, top_n: int = 20) -> Dict[str, Any]:
    """Open-alert breakdown plus opened/resolved counts over the window, for
    devices in scope, from the same ``alerts`` table every alert uses."""
    now = now or now_utc()
    since = (now - timedelta(days=window_days)).isoformat()
    empty = {"open_count": 0, "open_by_severity": {}, "open_by_device": {},
             "opened_count": 0, "resolved_count": 0, "top_open": []}
    if db is None or not device_ids:
        return empty
    marks = ",".join("?" * len(device_ids))
    open_rows = db.rows(
        f"SELECT * FROM alerts WHERE device_id IN ({marks}) AND resolved_at IS NULL "
        "ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC, "
        "opened_at DESC", list(device_ids))
    opened_count = db.scalar(
        f"SELECT COUNT(*) FROM alerts WHERE device_id IN ({marks}) AND opened_at>=?",
        [*device_ids, since]) or 0
    resolved_count = db.scalar(
        f"SELECT COUNT(*) FROM alerts WHERE device_id IN ({marks}) AND resolved_at>=?",
        [*device_ids, since]) or 0
    by_severity: Dict[str, int] = {}
    by_device: Dict[str, int] = {}
    for row in open_rows:
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        by_device[row["device_id"]] = by_device.get(row["device_id"], 0) + 1
    return {"open_count": len(open_rows), "open_by_severity": by_severity, "open_by_device": by_device,
            "opened_count": opened_count, "resolved_count": resolved_count, "top_open": open_rows[:top_n]}


def capacity_section(db: Any, device_ids: Sequence[str], devices_by_id: Dict[str, Dict[str, Any]],
                      now: Optional[datetime] = None, lookback_days: int = 14) -> List[Dict[str, Any]]:
    """Per-mount storage-growth forecast for devices in scope, via the exact
    same :func:`pinoc.history.storage_forecast` the per-device storage page
    and ``/api/devices/<id>/storage/forecast`` use."""
    from pinoc.history import storage_forecast
    now = now or now_utc()
    since = (now - timedelta(days=lookback_days)).isoformat()
    out: List[Dict[str, Any]] = []
    if db is None:
        return out
    for device_id in device_ids:
        rows = db.rows(
            "SELECT * FROM storage_metrics WHERE device_id=? AND timestamp>=? ORDER BY mount_point,timestamp",
            (device_id, since))
        for mount in sorted({row["mount_point"] for row in rows}):
            forecast = storage_forecast([row for row in rows if row["mount_point"] == mount])
            out.append({"device_id": device_id, "name": _device_label(devices_by_id, device_id),
                        "mount_point": mount, **forecast})
    return out


def storage_media_section(devices_by_id: Dict[str, Dict[str, Any]],
                           device_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Storage-media (SD card/USB/disk) health for devices in scope, from
    the same live ``media`` snapshot :meth:`pinoc.history.HistoryManager._alerts`
    opens ``media_io_errors`` alerts from -- no separate collection path."""
    out: List[Dict[str, Any]] = []
    for device_id in device_ids:
        device = devices_by_id.get(device_id, {})
        for medium in device.get("media") or []:
            out.append({"device_id": device_id, "name": _device_label(devices_by_id, device_id),
                        "block_device": medium.get("device"), "media_errors": bool(medium.get("media_errors")),
                        "io_errors": medium.get("io_errors"), "io_error_status": medium.get("io_error_status")})
    return out


def patch_status_section(db: Any, devices_by_id: Dict[str, Dict[str, Any]],
                          device_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Pending-update count (live device snapshot) plus the most recent
    :mod:`pinoc.rollout` run status touching each device in scope, if any."""
    latest_rollout: Dict[str, Dict[str, Any]] = {}
    if db is not None and device_ids:
        marks = ",".join("?" * len(device_ids))
        for row in db.rows(
                f"SELECT * FROM rollout_devices WHERE device_id IN ({marks}) ORDER BY updated_at DESC",
                list(device_ids)):
            latest_rollout.setdefault(row["device_id"], row)
    out = []
    for device_id in device_ids:
        device = devices_by_id.get(device_id, {})
        packages = (device.get("applications") or {}).get("packages") or {}
        rollout_row = latest_rollout.get(device_id)
        out.append({
            "device_id": device_id, "name": _device_label(devices_by_id, device_id),
            "updates_available": packages.get("updates_available"), "kernel": device.get("kernel") or None,
            "last_rollout_status": rollout_row.get("status") if rollout_row else None,
            "last_rollout_run_id": rollout_row.get("run_id") if rollout_row else None,
        })
    return out


SECTION_LABELS = {
    "uptime": "Uptime", "alerts": "Alert summary", "capacity": "Capacity forecast",
    "storage_media": "Storage media health", "patch_status": "Patch status",
}


def build_sections(definition: Dict[str, Any], db: Any = None, state: Any = None,
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """Resolve ``definition``'s scope against the current roster and build
    every requested content section from already-computed PiNOC data."""
    now = now or now_utc()
    devices = state.devices() if state is not None else []
    devices_by_id = {d["id"]: d for d in devices if d.get("id")}
    device_ids = resolve_scope_devices(definition["scope"], devices)
    sections: Dict[str, Any] = {}
    for name in definition["sections"]:
        if name == "uptime":
            sections["uptime"] = uptime_section(db, device_ids, devices_by_id, definition["window_days"], now)
        elif name == "alerts":
            sections["alerts"] = alerts_section(db, device_ids, definition["window_days"], now)
        elif name == "capacity":
            sections["capacity"] = capacity_section(db, device_ids, devices_by_id, now)
        elif name == "storage_media":
            sections["storage_media"] = storage_media_section(devices_by_id, device_ids)
        elif name == "patch_status":
            sections["patch_status"] = patch_status_section(db, devices_by_id, device_ids)
    return {"device_ids": device_ids, "sections": sections}


# -- rendering ------------------------------------------------------------------

def _esc(value: Any) -> str:
    if value is None:
        return "—"
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _pct(value: Optional[float]) -> str:
    return "insufficient data" if value is None else f"{value:.2f}%"


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return "<p>No data.</p>"
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _scope_label(scope: Dict[str, Any]) -> str:
    if scope.get("type") == "fleet":
        return "whole fleet"
    return f"{scope.get('type')}={scope.get('value')}"


def render_html(definition: Dict[str, Any], built: Dict[str, Any], generated_at: str) -> str:
    sections = built["sections"]
    parts = [
        f"<h1>{_esc(definition['name'])}</h1>",
        f"<p>Generated {_esc(generated_at)} &middot; scope {_esc(_scope_label(definition['scope']))} "
        f"&middot; {len(built['device_ids'])} device(s)</p>",
    ]
    if "uptime" in sections:
        u = sections["uptime"]
        parts.append(f"<h2>{SECTION_LABELS['uptime']}</h2>"
                     f"<p>Fleet attainment over {u['window_days']}d: {_pct(u['fleet_attainment_percent'])}</p>")
        parts.append(_table(["Device", "Online", "Attainment"],
                             [[r["name"], "yes" if r["online"] else "no", _pct(r["attainment_percent"])]
                              for r in u["devices"]]))
    if "alerts" in sections:
        a = sections["alerts"]
        parts.append(f"<h2>{SECTION_LABELS['alerts']}</h2>"
                     f"<p>{a['open_count']} open, {a['opened_count']} opened and {a['resolved_count']} "
                     f"resolved in the window.</p>")
        if a["open_by_severity"]:
            parts.append(_table(["Severity", "Open count"], sorted(a["open_by_severity"].items())))
        if a["top_open"]:
            parts.append(_table(["Device", "Type", "Severity", "Message", "Opened"],
                                 [[r.get("device_id"), r.get("alert_type"), r.get("severity"),
                                   r.get("message"), r.get("opened_at")] for r in a["top_open"]]))
    if "capacity" in sections:
        c = sections["capacity"]
        parts.append(f"<h2>{SECTION_LABELS['capacity']}</h2>")
        parts.append(_table(["Device", "Mount", "Status", "Days remaining", "Confidence"],
                             [[r["name"], r["mount_point"], r.get("status"),
                               r.get("estimated_days_remaining"), r.get("forecast_confidence")] for r in c]))
    if "storage_media" in sections:
        m = sections["storage_media"]
        parts.append(f"<h2>{SECTION_LABELS['storage_media']}</h2>")
        parts.append(_table(["Device", "Block device", "Media errors", "IO errors"],
                             [[r["name"], r["block_device"], "yes" if r["media_errors"] else "no",
                               r.get("io_errors")] for r in m]))
    if "patch_status" in sections:
        p = sections["patch_status"]
        parts.append(f"<h2>{SECTION_LABELS['patch_status']}</h2>")
        parts.append(_table(["Device", "Updates available", "Kernel", "Last rollout status"],
                             [[r["name"], r.get("updates_available"), r.get("kernel"),
                               r.get("last_rollout_status")] for r in p]))
    body = "".join(parts)
    return (f"<!doctype html><html><head><meta charset=\"utf-8\">"
            f"<title>{_esc(definition['name'])}</title></head><body>{body}</body></html>")


def render_csv(definition: Dict[str, Any], built: Dict[str, Any]) -> str:
    """One row per in-scope device, columns drawn from whichever sections
    the definition includes -- a per-alert/per-mount breakdown lives in the
    HTML edition; CSV stays one flat table for spreadsheet import."""
    sections = built["sections"]
    device_ids = built["device_ids"]
    uptime_by_id = {r["device_id"]: r for r in sections.get("uptime", {}).get("devices", [])}
    patch_by_id = {r["device_id"]: r for r in sections.get("patch_status", [])}
    open_alerts_by_id = sections.get("alerts", {}).get("open_by_device", {})
    media_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for r in sections.get("storage_media", []):
        media_by_id.setdefault(r["device_id"], []).append(r)
    capacity_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for r in sections.get("capacity", []):
        capacity_by_id.setdefault(r["device_id"], []).append(r)

    columns = ["device_id", "name"]
    if "uptime" in sections:
        columns += ["online", "attainment_percent"]
    if "alerts" in sections:
        columns += ["open_alerts"]
    if "patch_status" in sections:
        columns += ["updates_available", "kernel", "last_rollout_status"]
    if "storage_media" in sections:
        columns += ["media_error_count"]
    if "capacity" in sections:
        columns += ["worst_capacity_status", "min_days_remaining"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for device_id in device_ids:
        u = uptime_by_id.get(device_id, {})
        p = patch_by_id.get(device_id, {})
        name = u.get("name") or p.get("name") or device_id
        row = [device_id, name]
        if "uptime" in sections:
            row += ["yes" if u.get("online") else "no", u.get("attainment_percent")]
        if "alerts" in sections:
            row += [open_alerts_by_id.get(device_id, 0)]
        if "patch_status" in sections:
            row += [p.get("updates_available"), p.get("kernel"), p.get("last_rollout_status")]
        if "storage_media" in sections:
            media = media_by_id.get(device_id, [])
            row += [sum(1 for m in media if m.get("media_errors"))]
        if "capacity" in sections:
            caps = capacity_by_id.get(device_id, [])
            statuses = [c.get("status") for c in caps if c.get("status")]
            worst = "growing" if "growing" in statuses else (statuses[0] if statuses else "")
            remaining = [c.get("estimated_days_remaining") for c in caps if c.get("estimated_days_remaining") is not None]
            row += [worst, min(remaining) if remaining else ""]
        writer.writerow(row)
    return buf.getvalue()


def summarize(built: Dict[str, Any]) -> str:
    """A short plain-text summary suitable for a notification channel body
    (ntfy/SMTP/webhook all expect plain text, not a full HTML/CSV document
    -- see the module docstring's MVP-scope note)."""
    sections = built["sections"]
    bits = [f"{len(built['device_ids'])} device(s) in scope"]
    if "uptime" in sections:
        pct = sections["uptime"].get("fleet_attainment_percent")
        bits.append(f"uptime {pct:.2f}%" if pct is not None else "uptime: insufficient data")
    if "alerts" in sections:
        bits.append(f"{sections['alerts']['open_count']} alert(s) open")
    if "capacity" in sections:
        growing = sum(1 for c in sections["capacity"] if c.get("status") == "growing")
        if growing:
            bits.append(f"{growing} mount(s) filling")
    if "storage_media" in sections:
        bad = sum(1 for m in sections["storage_media"] if m.get("media_errors"))
        if bad:
            bits.append(f"{bad} storage media error(s)")
    if "patch_status" in sections:
        pending = sum(1 for p in sections["patch_status"] if (p.get("updates_available") or 0) > 0)
        if pending:
            bits.append(f"{pending} device(s) with pending updates")
    return "; ".join(bits)


# -- service: periodic render + deliver + archive ------------------------------

class ReportService:
    """Ticks on an interval: fires whichever report definitions are due
    (reusing :func:`pinoc.schedules.next_after` for "due"), renders and
    archives an edition, and delivers a short summary through the
    configured notification channel.

    ``db`` is the shared history :class:`~pinoc.database.Database`;
    ``state`` is the shared :class:`~pinoc.state.PiNOCState` (scope
    resolution reads the *current* roster on every firing, like
    :class:`pinoc.slo.SLOService`); ``notifications`` is the shared
    :class:`~pinoc.notifications.NotificationService`, used only for its
    channel list and :meth:`~pinoc.notifications.NotificationService.send_direct`.
    All three are optional: a missing one simply means fewer sections or no
    delivery, never an error.
    """

    def __init__(self, db: Any = None, state: Any = None, notifications: Any = None,
                 config: Optional[Dict[str, Any]] = None, interval: Optional[int] = None) -> None:
        cfg = config or {}
        self.db = db
        self.state = state
        self.notifications = notifications
        self.enabled = bool(cfg.get("enabled", True))
        self.definitions: List[Dict[str, Any]] = []
        for index, raw in enumerate(cfg.get("definitions") or []):
            try:
                self.definitions.append(parse_report(raw, index))
            except ReportConfigError:
                # Config is validated at save time (pinoc.config_store); a
                # bad entry here means the file was hand-edited after the
                # fact. Skip it rather than taking the whole service down.
                LOG.warning("skipping invalid report definition #%d in loaded config", index)
        self.retention = max(1, int(cfg.get("edition_retention", 90)))
        self.interval = max(5, int(interval if interval is not None else cfg.get("interval_seconds", 60)))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-reports", daemon=True)

    # -- lifecycle ---------------------------------------------------------
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
                LOG.exception("report tick failed")
            self.stop_event.wait(self.interval)

    # -- engine --------------------------------------------------------------
    def tick(self, now: Optional[datetime] = None) -> None:
        if self.db is None or not self.db.available:
            return
        now = now or now_utc()
        for definition in self.definitions:
            if not definition.get("enabled", True):
                continue
            try:
                self._maybe_fire(definition, now)
            except Exception:
                LOG.exception("report %s tick failed", definition.get("id"))

    def _schedule_row(self, report_id: str) -> Optional[Dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM report_schedule_state WHERE report_id=?", (report_id,))
        return rows[0] if rows else None

    def _ensure_next_run(self, definition: Dict[str, Any], now: datetime) -> Optional[datetime]:
        row = self._schedule_row(definition["id"])
        if row is not None:
            return datetime.fromisoformat(row["next_run"]) if row.get("next_run") else None
        next_run = next_after(definition["spec"], now, definition["timezone"])
        self.db.execute(
            "INSERT INTO report_schedule_state(report_id,next_run,updated_at) VALUES(?,?,?)",
            (definition["id"], next_run.isoformat() if next_run else None, utcnow()))
        return next_run

    def _maybe_fire(self, definition: Dict[str, Any], now: datetime) -> None:
        next_run = self._ensure_next_run(definition, now)
        if next_run is None or next_run > now:
            return
        try:
            self.generate(definition, now=now)
        finally:
            new_next = next_after(definition["spec"], now, definition["timezone"])
            self.db.execute(
                "UPDATE report_schedule_state SET next_run=?,last_run=?,updated_at=? WHERE report_id=?",
                (new_next.isoformat() if new_next else None, now.isoformat(), utcnow(), definition["id"]))

    # -- generation, delivery, archival ---------------------------------------
    def generate(self, definition: Dict[str, Any], now: Optional[datetime] = None) -> int:
        """Render one edition of ``definition`` right now, deliver it, and
        archive it. Returns the new edition's row id. Used by both the tick
        loop (a due schedule) and the "run now" API."""
        now = now or now_utc()
        built = build_sections(definition, self.db, self.state, now)
        content = (render_html(definition, built, now.isoformat()) if definition["format"] == "html"
                   else render_csv(definition, built))
        edition_id = self.db.execute(
            "INSERT INTO report_editions(report_id,name,generated_at,format,scope_json,sections_json,"
            "device_count,content,delivered,delivery_error) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (definition["id"], definition["name"], now.isoformat(), definition["format"],
             json.dumps(definition["scope"]), json.dumps(definition["sections"]), len(built["device_ids"]),
             content, 0, None))
        ok, error = self._deliver(definition, built, now)
        self.db.execute("UPDATE report_editions SET delivered=?,delivery_error=? WHERE id=?",
                        (1 if ok else 0, error, edition_id))
        self._prune(definition["id"])
        return edition_id

    def _deliver(self, definition: Dict[str, Any], built: Dict[str, Any],
                 now: datetime) -> "tuple[bool, Optional[str]]":
        if self.notifications is None:
            return False, "notifications are not configured"
        channel = next((c for c in self.notifications.channels() if c.get("id") == definition["channel_id"]), None)
        if channel is None:
            return False, f"channel {definition['channel_id']!r} not found"
        subject = f"PiNOC report: {definition['name']} ({now.date().isoformat()})"
        body = (f"{definition['name']}: {summarize(built)}. "
                f"View the full {definition['format'].upper()} edition on the PiNOC Reports page.")
        try:
            return self.notifications.send_direct(channel, subject, body)
        except Exception as exc:  # noqa: BLE001 - a delivery failure must not lose the rendered edition
            LOG.warning("report delivery failed for %s: %s", definition["id"], exc)
            return False, str(exc)

    def _prune(self, report_id: str) -> None:
        rows = self.db.rows(
            "SELECT id FROM report_editions WHERE report_id=? ORDER BY generated_at DESC", (report_id,))
        for row in rows[self.retention:]:
            self.db.execute("DELETE FROM report_editions WHERE id=?", (row["id"],))

    # -- reads: the Reports page reads all of this directly -------------------
    def get_definition(self, report_id: str) -> Optional[Dict[str, Any]]:
        return next((dict(d) for d in self.definitions if d["id"] == report_id), None)

    def run_now(self, report_id: str, now: Optional[datetime] = None) -> int:
        definition = self.get_definition(report_id)
        if definition is None:
            raise ValueError("report not found")
        return self.generate(definition, now=now)

    def status(self) -> Dict[str, Any]:
        by_id = {row["report_id"]: row for row in self.db.rows("SELECT * FROM report_schedule_state")} \
            if self.db is not None else {}
        out = []
        for definition in self.definitions:
            state_row = by_id.get(definition["id"], {})
            out.append({**definition, "next_run": state_row.get("next_run"), "last_run": state_row.get("last_run")})
        return {"running": self.thread.is_alive(), "reports": out}

    def editions(self, report_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        if self.db is None:
            return []
        columns = "id,report_id,name,generated_at,format,scope_json,sections_json,device_count,delivered,delivery_error"
        if report_id:
            return self.db.rows(
                f"SELECT {columns} FROM report_editions WHERE report_id=? ORDER BY generated_at DESC LIMIT ?",
                (report_id, limit))
        return self.db.rows(f"SELECT {columns} FROM report_editions ORDER BY generated_at DESC LIMIT ?", (limit,))

    def edition(self, edition_id: int) -> Optional[Dict[str, Any]]:
        if self.db is None:
            return None
        rows = self.db.rows("SELECT * FROM report_editions WHERE id=?", (edition_id,))
        return rows[0] if rows else None
