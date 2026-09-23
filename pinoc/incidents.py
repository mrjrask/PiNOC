"""Incident timelines and automatic post-mortems.

When a correlated alert cluster (see ``pinoc.correlation``) or a standalone
alert resolves, this module synthesizes one *incident* record: a
chronological timeline of every alert transition, related action job, and
notification, plus computed MTTA (time to first acknowledgment) and MTTR
(time to resolution) and the list of devices involved. The goal is to turn
what would otherwise be manual archaeology across the alerts/events/audit/
notifications pages into one shareable record once an incident is over.

Design choices (see also the ``incidents`` table in ``pinoc.database``):

* **Trigger**: hooked directly into ``HistoryManager._correlate()`` (see
  ``pinoc/history.py``), which already knows, on every reconcile pass,
  exactly which clusters and standalone alerts just resolved. No separate
  polling loop is needed -- synthesis happens inline, in the same
  non-blocking history-writer thread, the moment a resolution is observed.
* **Storage**: the incident row stores only *references* -- which
  cluster/alert it came from, the alert_ids and device_ids involved, and
  the computed MTTA/MTTR/title -- never a duplicate copy of the underlying
  alert/event/action/notification rows. ``build_timeline()`` reconstructs
  the full story at read time by querying ``alerts``, ``events``,
  ``action_jobs``, and ``notification_log`` for that incident's alert_ids/
  device_ids and time window. This keeps a resolved incident live: if an
  alert's message or an action's summary is ever corrected, the incident
  reflects it without re-synthesis.
* **Standalone alerts**: an alert that resolves without ever joining a
  cluster still gets a (smaller, single-alert) incident record, matching
  the feature spec's "or any alert" language. An alert that belongs to a
  cluster is only ever represented by that cluster's incident, never both.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .correlation import describe_context, trigger_class as _trigger_class

LOG = logging.getLogger("pinoc.incidents")
UTC = timezone.utc


# -- time helpers ----------------------------------------------------------

def _parse(stamp: Optional[str]) -> Optional[datetime]:
    if not stamp:
        return None
    try:
        value = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _seconds_between(start: Optional[str], end: Optional[str]) -> Optional[float]:
    a, b = _parse(start), _parse(end)
    if a is None or b is None:
        return None
    return max(0.0, (b - a).total_seconds())


def _now() -> str:
    return datetime.now(UTC).isoformat()


def format_duration(seconds: Optional[float]) -> str:
    """Human-readable duration for MTTA/MTTR display (e.g. "1h 4m 12s")."""
    if seconds is None:
        return "n/a"
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if hours or minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _mtta(alerts: List[Dict[str, Any]], opened_at: Optional[str]) -> Optional[float]:
    """Seconds from incident open to the *first* acknowledgment across every
    member alert, or None when nothing was ever acknowledged."""
    acked = [a["acknowledged_at"] for a in alerts if a.get("acknowledged_at")]
    if not acked:
        return None
    return _seconds_between(opened_at, min(acked))


# -- synthesis ---------------------------------------------------------------

def synthesize_cluster(db: Any, cluster: Dict[str, Any]) -> Optional[int]:
    """Create the incident record for a just-resolved alert cluster.

    Idempotent: a cluster observed as resolved more than once (defensive;
    correlation only reports it once today) never creates a duplicate row.
    """
    existing = db.scalar(
        "SELECT incident_id FROM incidents WHERE kind='cluster' AND source_id=?", (cluster["cluster_id"],))
    if existing:
        return int(existing)
    members = db.rows("SELECT * FROM alerts WHERE cluster_id=?", (cluster["cluster_id"],))
    if not members:
        return None
    device_ids = sorted({m["device_id"] for m in members if m.get("device_id")})
    alert_ids = sorted(m["alert_id"] for m in members)
    opened_at = cluster.get("opened_at") or min(m["opened_at"] for m in members)
    resolved_at = cluster.get("resolved_at") or max(
        (m.get("resolved_at") for m in members if m.get("resolved_at")), default=opened_at)
    try:
        label = json.loads(cluster.get("context_json") or "{}").get("label")
    except (TypeError, ValueError):
        label = None
    context = describe_context(cluster.get("context_key", ""), cluster.get("context_value", ""), label)
    title = f"{str(cluster.get('trigger_class') or 'incident').replace('_', ' ').title()} incident · {context}"
    incident_id = db.execute(
        "INSERT INTO incidents(kind,source_id,trigger_class,title,severity,opened_at,resolved_at,"
        "mtta_seconds,mttr_seconds,device_ids_json,alert_ids_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("cluster", cluster["cluster_id"], cluster.get("trigger_class", ""), title, cluster.get("severity", "info"),
         opened_at, resolved_at, _mtta(members, opened_at), _seconds_between(opened_at, resolved_at),
         json.dumps(device_ids), json.dumps(alert_ids), _now()))
    return incident_id or None


def synthesize_alert(db: Any, alert: Dict[str, Any]) -> Optional[int]:
    """Create the (smaller, single-alert) incident record for a standalone
    alert that resolved without ever joining a cluster. Returns None for an
    alert that *did* join a cluster -- that story belongs to the cluster's
    incident instead (see ``synthesize_cluster``)."""
    if alert.get("cluster_id"):
        return None
    existing = db.scalar(
        "SELECT incident_id FROM incidents WHERE kind='alert' AND source_id=?", (alert["alert_id"],))
    if existing:
        return int(existing)
    opened_at = alert.get("opened_at")
    resolved_at = alert.get("resolved_at") or _now()
    device_id = alert.get("device_id")
    title = f"{str(alert.get('alert_type') or 'alert').replace('_', ' ').title()} · {device_id or 'unknown device'}"
    incident_id = db.execute(
        "INSERT INTO incidents(kind,source_id,trigger_class,title,severity,opened_at,resolved_at,"
        "mtta_seconds,mttr_seconds,device_ids_json,alert_ids_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("alert", alert["alert_id"], _trigger_class(alert.get("alert_type", "")), title, alert.get("severity", "info"),
         opened_at, resolved_at, _mtta([alert], opened_at), _seconds_between(opened_at, resolved_at),
         json.dumps([device_id] if device_id else []), json.dumps([alert["alert_id"]]), _now()))
    return incident_id or None


# -- reads ---------------------------------------------------------------

def _decorate(row: Dict[str, Any]) -> Dict[str, Any]:
    try:
        device_ids = json.loads(row.get("device_ids_json") or "[]")
    except (TypeError, ValueError):
        device_ids = []
    try:
        alert_ids = json.loads(row.get("alert_ids_json") or "[]")
    except (TypeError, ValueError):
        alert_ids = []
    return {**row, "device_ids": device_ids, "alert_ids": alert_ids}


def get_incident(db: Any, incident_id: int) -> Optional[Dict[str, Any]]:
    rows = db.rows("SELECT * FROM incidents WHERE incident_id=?", (incident_id,))
    return _decorate(rows[0]) if rows else None


def list_incidents(db: Any, *, device: Optional[str] = None, severity: Optional[str] = None,
                    since: Optional[str] = None, until: Optional[str] = None,
                    limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
    where, args = ["1=1"], []
    if device:
        where.append("device_ids_json LIKE ?")
        args.append(f'%"{device}"%')
    if severity:
        where.append("severity=?")
        args.append(severity)
    if since:
        where.append("resolved_at>=?")
        args.append(since)
    if until:
        where.append("resolved_at<=?")
        args.append(until)
    clause = " AND ".join(where)
    total = db.scalar(f"SELECT COUNT(*) FROM incidents WHERE {clause}", args) or 0
    rows = db.rows(
        f"SELECT * FROM incidents WHERE {clause} ORDER BY resolved_at DESC LIMIT ? OFFSET ?",
        args + [limit, offset])
    return [_decorate(row) for row in rows], total


def incident_id_for_alert(db: Any, alert: Dict[str, Any]) -> Optional[int]:
    """The incident an already-resolved alert belongs to, if one has been
    synthesized yet -- used to link a resolved alert card to its incident."""
    if alert.get("cluster_id"):
        row = db.scalar(
            "SELECT incident_id FROM incidents WHERE kind='cluster' AND source_id=?", (alert["cluster_id"],))
    else:
        row = db.scalar(
            "SELECT incident_id FROM incidents WHERE kind='alert' AND source_id=?", (alert["alert_id"],))
    return int(row) if row else None


def build_timeline(db: Any, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reconstruct the chronological timeline for an incident from the
    existing alerts/events/action_jobs/notification_log tables -- nothing
    here is read from the incident row itself beyond which alerts/devices/
    window it covers."""
    device_ids: List[str] = incident.get("device_ids") or []
    alert_ids: List[int] = incident.get("alert_ids") or []
    entries: List[Dict[str, Any]] = []

    if alert_ids:
        placeholders = ",".join("?" * len(alert_ids))
        for alert in db.rows(f"SELECT * FROM alerts WHERE alert_id IN ({placeholders})", alert_ids):
            device_id = alert.get("device_id")
            if alert.get("opened_at"):
                entries.append({"time": alert["opened_at"], "kind": "alert_opened", "device_id": device_id,
                                 "severity": alert.get("severity"), "alert_id": alert["alert_id"],
                                 "description": f"Alert opened: {alert.get('message')}"})
            if alert.get("acknowledged_at"):
                entries.append({"time": alert["acknowledged_at"], "kind": "alert_acknowledged", "device_id": device_id,
                                 "severity": alert.get("severity"), "alert_id": alert["alert_id"],
                                 "description": f"Acknowledged by {alert.get('acknowledged_by') or 'unknown'}"})
            if alert.get("resolved_at"):
                entries.append({"time": alert["resolved_at"], "kind": "alert_resolved", "device_id": device_id,
                                 "severity": alert.get("severity"), "alert_id": alert["alert_id"],
                                 "description": f"Alert resolved: {alert.get('message')}"})

    window_start = incident.get("opened_at") or ""
    window_end = incident.get("resolved_at") or _now()
    if device_ids:
        placeholders = ",".join("?" * len(device_ids))
        for event in db.rows(
                f"SELECT * FROM events WHERE device_id IN ({placeholders}) AND timestamp>=? AND timestamp<=? "
                "ORDER BY timestamp", [*device_ids, window_start, window_end]):
            entries.append({"time": event["timestamp"], "kind": f"event:{event['event_type']}",
                             "device_id": event.get("device_id"), "severity": event.get("severity"),
                             "description": event.get("message")})
        for job in db.rows(
                f"SELECT * FROM action_jobs WHERE device_id IN ({placeholders}) AND requested_at>=? AND requested_at<=? "
                "ORDER BY requested_at", [*device_ids, window_start, window_end]):
            entries.append({"time": job["requested_at"], "kind": "action_requested", "device_id": job.get("device_id"),
                             "job_id": job.get("job_id"),
                             "description": f"{job.get('action')} requested by {job.get('requested_by')}"
                                            + (f" targeting {job.get('target')}" if job.get("target") else "")})
            if job.get("completed_at"):
                summary = f": {job.get('summary')}" if job.get("summary") else ""
                entries.append({"time": job["completed_at"], "kind": "action_completed", "device_id": job.get("device_id"),
                                 "job_id": job.get("job_id"),
                                 "description": f"{job.get('action')} {job.get('status')}{summary}"})
        for note in db.rows(
                f"SELECT * FROM notification_log WHERE device_id IN ({placeholders}) AND timestamp>=? AND timestamp<=? "
                "ORDER BY timestamp", [*device_ids, window_start, window_end]):
            entries.append(_notification_entry(note))
    if incident.get("kind") == "cluster":
        # Cluster-wide notifications carry device_id=NULL (see
        # HistoryManager._notify_cluster in pinoc/history.py) -- they
        # describe the whole cluster, not one member device.
        for note in db.rows(
                "SELECT * FROM notification_log WHERE device_id IS NULL AND timestamp>=? AND timestamp<=? "
                "ORDER BY timestamp", (window_start, window_end)):
            entries.append(_notification_entry(note))

    entries.sort(key=lambda entry: entry.get("time") or "")
    return entries


def _notification_entry(note: Dict[str, Any]) -> Dict[str, Any]:
    outcome = "sent" if note.get("ok") else f"failed: {note.get('error')}"
    return {"time": note["timestamp"], "kind": "notification", "device_id": note.get("device_id"),
            "description": f"{note.get('transition')} notification via {note.get('channel_kind') or note.get('channel_id')} ({outcome})"}


# -- exports ---------------------------------------------------------------

def to_markdown(incident: Dict[str, Any], timeline: List[Dict[str, Any]]) -> str:
    lines = [
        f"# {incident.get('title', 'Incident')}", "",
        f"- **Severity:** {incident.get('severity')}",
        f"- **Opened:** {incident.get('opened_at')}",
        f"- **Resolved:** {incident.get('resolved_at')}",
        f"- **MTTA:** {format_duration(incident.get('mtta_seconds'))}",
        f"- **MTTR:** {format_duration(incident.get('mttr_seconds'))}",
        f"- **Devices involved:** {', '.join(incident.get('device_ids') or []) or 'none'}",
        "", "## Timeline", "",
    ]
    for entry in timeline:
        who = entry.get("device_id") or "cluster"
        lines.append(f"- `{entry.get('time')}` **{entry.get('kind')}** ({who}) — {entry.get('description')}")
    if not timeline:
        lines.append("_No timeline entries recorded._")
    return "\n".join(lines) + "\n"


def to_json(incident: Dict[str, Any], timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"incident": incident, "timeline": timeline}


def _esc(value: Any) -> str:
    return (str(value) if value is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def to_html(incident: Dict[str, Any], timeline: List[Dict[str, Any]]) -> str:
    """A standalone, print-friendly HTML view of one incident -- no
    navigation chrome, just the record and its timeline, so it can be
    printed to PDF from the browser or opened on its own."""
    rows = "".join(
        f"<tr><td>{_esc(entry.get('time'))}</td><td>{_esc(entry.get('kind'))}</td>"
        f"<td>{_esc(entry.get('device_id') or 'cluster')}</td><td>{_esc(entry.get('description'))}</td></tr>"
        for entry in timeline
    ) or "<tr><td colspan=\"4\">No timeline entries recorded.</td></tr>"
    devices = ", ".join(incident.get("device_ids") or []) or "none"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(incident.get('title'))} · PiNOC incident</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}
h1{{margin-bottom:.25rem}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem;vertical-align:top}}
th{{background:#f2f2f2}} dl{{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}}
dt{{font-weight:600}} @media print{{a{{color:inherit;text-decoration:none}}}}
</style></head>
<body>
<h1>{_esc(incident.get('title'))}</h1>
<dl>
<dt>Severity</dt><dd>{_esc(incident.get('severity'))}</dd>
<dt>Opened</dt><dd>{_esc(incident.get('opened_at'))}</dd>
<dt>Resolved</dt><dd>{_esc(incident.get('resolved_at'))}</dd>
<dt>MTTA</dt><dd>{_esc(format_duration(incident.get('mtta_seconds')))}</dd>
<dt>MTTR</dt><dd>{_esc(format_duration(incident.get('mttr_seconds')))}</dd>
<dt>Devices involved</dt><dd>{_esc(devices)}</dd>
</dl>
<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Kind</th><th>Device</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>
"""
