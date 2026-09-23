"""Customizable dashboards, saved fleet-filter presets, and the Glance view.

A *preset* is a small, per-user, named blob of JSON persisted in the
``user_presets`` table (see :mod:`pinoc.database`).  Two ``kind``s share the
same table and the same :class:`PresetStore` CRUD:

* ``dashboard``    -- an ordered list of *cards* (each referencing one of the
  fixed :data:`CARD_TYPES`, plus its own config and grid position) that
  composes a personal home-page-style layout, saved under a name and loaded
  again by a stable ``preset_id`` (the basis for a shareable URL: ``/dashboards/<id>``
  and ``/glance?preset=<id>``).
* ``fleet_filter`` -- a saved health/role/tag/search/sort combination for the
  fleet page's device list, so a VPN administrator or a file-server operator
  can jump straight to "their" devices.

Card *types* are a fixed catalog (the "card library") backed entirely by data
PiNOC already collects -- nothing here talks to a device or the network.
:func:`resolve_card` turns one card's ``{type, config}`` into the live values
it should display; :func:`resolve_dashboard` does this for every card in a
saved (or default) dashboard payload in one pass, which is what both the
dashboard composer and the Glance view render from.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from pinoc.database import utcnow
from pinoc.history import storage_forecast as _storage_forecast

UTC = timezone.utc

VALID_KINDS = {"dashboard", "fleet_filter"}

# The card library: a fixed set of card types, each backed by data already
# available from the shared state cache (pinoc.state.PiNOCState) or, where
# noted, the history database. ``fields`` describes the config a card of
# this type accepts, for a composer UI to render a config form from -- it is
# advisory only; resolve_card() degrades gracefully (an "error" on the
# resolved card, never an exception) for a bad or stale config, e.g. a
# device that has since been removed.
CARD_TYPES: Dict[str, Dict[str, Any]] = {
    "device_health": {
        "label": "Device health",
        "description": "Health, online status, and last-seen time for one device.",
        "fields": [{"name": "device_id", "type": "device", "required": True}],
    },
    "device_metric": {
        "label": "Device metric",
        "description": "A single live metric for one device.",
        "fields": [
            {"name": "device_id", "type": "device", "required": True},
            {"name": "metric", "type": "enum", "required": True,
             "options": ["cpu_percent", "cpu_temperature_c", "memory_percent",
                         "disk_percent", "uptime_seconds"]},
        ],
    },
    "fleet_summary": {
        "label": "Fleet summary",
        "description": "Device counts by health state across the whole fleet.",
        "fields": [],
    },
    "fleet_alert_count": {
        "label": "Alert count",
        "description": "Count of active alerts, optionally filtered by severity.",
        "fields": [{"name": "severity", "type": "enum", "required": False,
                     "options": ["", "info", "warning", "degraded", "critical"]}],
    },
    "fleet_aggregate": {
        "label": "Fleet aggregate",
        "description": "A fleet-wide rollup metric averaged or summed across online devices.",
        "fields": [{"name": "field", "type": "enum", "required": True,
                     "options": ["cpu_average_percent", "memory_average_percent",
                                 "cpu_max_temperature_c", "storage_average_percent",
                                 "rx_rate_bps", "tx_rate_bps"]}],
    },
    "storage_forecast": {
        "label": "Storage forecast",
        "description": "Fleet-wide storage growth trend and estimated days to full (needs history).",
        "fields": [],
    },
    "alert_list": {
        "label": "Active alerts",
        "description": "A short list of the highest-severity active alerts.",
        "fields": [{"name": "limit", "type": "number", "required": False, "default": 5}],
    },
    "slo_summary": {
        "label": "SLO reliability",
        "description": "Rolling attainment and error-budget burn for one configured SLO "
                        "(see the top-level `slos` config section).",
        "fields": [{"name": "slo_id", "type": "slo", "required": True}],
    },
}


def card_library() -> List[Dict[str, Any]]:
    return [{"type": key, **value} for key, value in CARD_TYPES.items()]


# -- card data resolution ---------------------------------------------------

def _device_metric_value(device: Dict[str, Any], metric: str) -> Any:
    if metric == "cpu_percent":
        return (device.get("cpu") or {}).get("utilization_percent")
    if metric == "cpu_temperature_c":
        return (device.get("cpu") or {}).get("temperature_c")
    if metric == "memory_percent":
        return (device.get("memory") or {}).get("percent")
    if metric == "disk_percent":
        values = [x.get("percent") for x in device.get("storage", []) if x.get("percent") is not None]
        return round(max(values), 1) if values else None
    if metric == "uptime_seconds":
        return device.get("uptime_seconds")
    return None


def _average(values: List[Optional[float]]) -> Optional[float]:
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None


def _fleet_live_field(devices: List[Dict[str, Any]], field: str) -> Any:
    online = [d for d in devices if d.get("online")]
    if field == "cpu_average_percent":
        return _average([(d.get("cpu") or {}).get("utilization_percent") for d in online])
    if field == "memory_average_percent":
        return _average([(d.get("memory") or {}).get("percent") for d in online])
    if field == "cpu_max_temperature_c":
        temps = [(d.get("cpu") or {}).get("temperature_c") for d in online]
        temps = [t for t in temps if t is not None]
        return round(max(temps), 1) if temps else None
    if field == "storage_average_percent":
        percents = [x.get("percent") for d in online for x in d.get("storage", []) if x.get("percent") is not None]
        return _average(percents)
    if field == "rx_rate_bps":
        return sum(int((d.get("network") or {}).get("rx_rate") or 0) for d in online) or None
    if field == "tx_rate_bps":
        return sum(int((d.get("network") or {}).get("tx_rate") or 0) for d in online) or None
    return None


def _fleet_storage_forecast(devices: List[Dict[str, Any]], history: Any) -> Optional[Dict[str, Any]]:
    """Fleet-wide storage-growth forecast, mirroring the dashboard's own
    fleet_aggregates() rollup in pinoc.web.app but computed independently
    here so this module has no dependency on the web layer."""
    if history is None or not getattr(history, "db", None) or not history.db.available:
        return None
    online = [d for d in devices if d.get("online")]
    mounts: List[tuple] = []
    for device in online:
        for entry in device.get("storage", []):
            total = int(entry.get("total") or 0)
            if total:
                mounts.append((device.get("id"), entry.get("mount_point") or entry.get("path") or "",
                                int(entry.get("used") or 0)))
    top_mounts = [(device_id, mount) for device_id, mount, _used
                  in sorted(mounts, key=lambda item: -item[2])[:12] if mount]
    if not top_mounts:
        return {"status": "insufficient", "estimated_days_remaining": None}
    now = datetime.now(UTC)
    window_start = (now - timedelta(days=30)).isoformat()
    device_ids = sorted({device_id for device_id, _mount in top_mounts})
    placeholders = ",".join("?" * len(device_ids))
    rows_by_pair: Dict[tuple, List[Dict[str, Any]]] = {}
    for row in history.db.rows(
            f"SELECT device_id,mount_point,timestamp,used_bytes,total_bytes FROM storage_metrics "
            f"WHERE device_id IN ({placeholders}) AND timestamp>=? ORDER BY device_id,mount_point,timestamp",
            (*device_ids, window_start)):
        rows_by_pair.setdefault((row["device_id"], row["mount_point"]), []).append(row)
    days: List[float] = []
    statuses: List[str] = []
    for device_id, mount in top_mounts:
        forecast = _storage_forecast(rows_by_pair.get((device_id, mount), []))
        statuses.append(forecast["status"])
        if forecast.get("estimated_days_remaining") is not None:
            days.append(forecast["estimated_days_remaining"])
    if days:
        status = "growing"
    elif "stable" in statuses:
        status = "stable"
    elif "decreasing" in statuses:
        status = "decreasing"
    else:
        status = statuses[0] if statuses else "insufficient"
    return {"status": status, "estimated_days_remaining": round(min(days), 1) if days else None}


def resolve_card(card: Dict[str, Any], state: Any, history: Any = None, slo_service: Any = None) -> Dict[str, Any]:
    """Turn one ``{id, type, config}`` card into its live display data.

    Never raises: an unknown type, a missing device, or a config that no
    longer makes sense (a device that has since been removed) comes back as
    ``{"error": "..."}`` with ``data`` left ``None``, so one broken card in a
    saved dashboard never breaks the rest.
    """
    card_id = card.get("id")
    ctype = str(card.get("type") or "")
    config = card.get("config") if isinstance(card.get("config"), dict) else {}
    spec = CARD_TYPES.get(ctype)
    result: Dict[str, Any] = {"id": card_id, "type": ctype, "config": config,
                                "title": card.get("title") or (spec["label"] if spec else ctype),
                                "data": None, "error": None}
    if spec is None:
        result["error"] = f"unknown card type: {ctype}"
        return result
    try:
        if ctype == "device_health":
            device_id = config.get("device_id")
            device = state.device(device_id) if device_id else None
            if device is None:
                result["error"] = "device not found"
                return result
            result["data"] = {"device_id": device["id"], "friendly_name": device.get("friendly_name"),
                               "health": device.get("health"), "online": device.get("online"),
                               "stale": device.get("stale"), "last_seen": device.get("last_seen")}
        elif ctype == "device_metric":
            device_id = config.get("device_id")
            metric = config.get("metric")
            device = state.device(device_id) if device_id else None
            if device is None:
                result["error"] = "device not found"
                return result
            result["data"] = {"device_id": device["id"], "friendly_name": device.get("friendly_name"),
                               "metric": metric, "value": _device_metric_value(device, metric)}
        elif ctype == "fleet_summary":
            result["data"] = state.summary()
        elif ctype == "fleet_alert_count":
            severity = str(config.get("severity") or "").strip().lower()
            alerts = [a for a in state.alerts() if a.get("state") == "active"]
            if severity:
                alerts = [a for a in alerts if str(a.get("severity")) == severity]
            result["data"] = {"severity": severity or "all", "count": len(alerts)}
        elif ctype == "fleet_aggregate":
            field = str(config.get("field") or "")
            result["data"] = {"field": field, "value": _fleet_live_field(state.devices(), field)}
        elif ctype == "storage_forecast":
            result["data"] = _fleet_storage_forecast(state.devices(), history)
        elif ctype == "alert_list":
            try:
                limit = min(20, max(1, int(config.get("limit") or 5)))
            except (TypeError, ValueError):
                limit = 5
            ranks = {"critical": 3, "degraded": 2, "warning": 1, "info": 0}
            alerts = [a for a in state.alerts() if a.get("state") == "active"]
            alerts.sort(key=lambda a: -ranks.get(str(a.get("severity")), 0))
            result["data"] = {
                "total": len(alerts),
                "alerts": [{"device_id": a.get("device_id"), "severity": a.get("severity"),
                            "message": a.get("message")} for a in alerts[:limit]],
            }
        elif ctype == "slo_summary":
            slo_id = str(config.get("slo_id") or "")
            if slo_service is None:
                result["error"] = "SLO service not available"
                return result
            entry = slo_service.get_one(slo_id) if slo_id else None
            if entry is None:
                result["error"] = "SLO not found"
                return result
            result["data"] = entry
    except Exception as exc:  # noqa: BLE001 - one bad card must not break the page
        result["error"] = str(exc)
        result["data"] = None
    return result


def resolve_dashboard(payload: Dict[str, Any], state: Any, history: Any = None,
                       slo_service: Any = None) -> List[Dict[str, Any]]:
    return [resolve_card(card, state, history, slo_service) for card in (payload or {}).get("cards", [])]


def default_glance_cards(state: Any, limit: int = 6) -> Dict[str, Any]:
    """A sensible default for the Glance view when no preset is requested:
    fleet summary, active-alert count, and the worst-health devices."""
    cards: List[Dict[str, Any]] = [
        {"id": "summary", "type": "fleet_summary", "config": {}},
        {"id": "alerts", "type": "fleet_alert_count", "config": {}},
    ]
    ranks = {"critical": 0, "offline": 1, "degraded": 2, "warning": 3, "healthy": 4, "maintenance": 5}
    devices = sorted(state.devices(), key=lambda d: ranks.get(d.get("health"), 9))[:max(0, limit)]
    for device in devices:
        cards.append({"id": f"device-{device['id']}", "type": "device_health",
                       "config": {"device_id": device["id"]}})
    return {"cards": cards}


# -- payload validation -------------------------------------------------

def validate_dashboard_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("invalid dashboard payload")
    cards = payload.get("cards")
    if not isinstance(cards, list):
        raise ValueError("dashboard payload needs a list of cards")
    if len(cards) > 60:
        raise ValueError("too many cards (max 60)")
    normalized = []
    for index, raw in enumerate(cards):
        if not isinstance(raw, dict):
            raise ValueError("each card must be an object")
        ctype = str(raw.get("type") or "")
        if ctype not in CARD_TYPES:
            raise ValueError(f"unknown card type: {ctype}")
        config = raw.get("config") if isinstance(raw.get("config"), dict) else {}
        try:
            width = max(1, min(6, int(raw.get("w") or 2)))
            height = max(1, min(4, int(raw.get("h") or 1)))
            x = max(0, int(raw.get("x") or 0))
            y = max(0, int(raw.get("y") or 0))
        except (TypeError, ValueError):
            raise ValueError("card position/size must be numbers")
        normalized.append({
            "id": str(raw.get("id") or f"card-{index}")[:64],
            "type": ctype,
            "title": str(raw.get("title") or "")[:120],
            "config": config,
            "x": x, "y": y, "w": width, "h": height,
        })
    return {"cards": normalized}


def validate_filter_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("invalid filter payload")
    return {
        "health": str(payload.get("health") or "")[:32],
        "role": str(payload.get("role") or "")[:64],
        "tag": str(payload.get("tag") or "")[:64],
        "search": str(payload.get("search") or "")[:200],
        "sort": str(payload.get("sort") or "")[:32],
    }


VALIDATORS = {"dashboard": validate_dashboard_payload, "fleet_filter": validate_filter_payload}


# -- persistence --------------------------------------------------------

class PresetStore:
    """CRUD for the ``user_presets`` table, shared by both preset kinds."""

    def __init__(self, db: Any) -> None:
        self.db = db

    def _decode(self, row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            payload = {}
        return {"preset_id": row["preset_id"], "owner": row["owner"], "kind": row["kind"],
                "name": row["name"], "payload": payload,
                "created_at": row["created_at"], "updated_at": row["updated_at"]}

    def list(self, owner: str, kind: str) -> List[Dict[str, Any]]:
        rows = self.db.rows(
            "SELECT * FROM user_presets WHERE owner=? AND kind=? ORDER BY updated_at DESC",
            (owner, kind))
        return [self._decode(row) for row in rows]

    def get(self, preset_id: str) -> Optional[Dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM user_presets WHERE preset_id=?", (preset_id,))
        return self._decode(rows[0]) if rows else None

    def create(self, owner: str, kind: str, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if kind not in VALID_KINDS:
            raise ValueError("invalid preset kind")
        name = str(name or "").strip()
        if not name:
            raise ValueError("a preset needs a name")
        payload = VALIDATORS[kind](payload)
        preset_id = uuid.uuid4().hex
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO user_presets(preset_id,owner,kind,name,payload_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (preset_id, owner, kind, name[:200], json.dumps(payload), stamp, stamp))
        return self.get(preset_id)

    def update(self, preset_id: str, owner: str, *, name: Optional[str] = None,
               payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        row = self.get(preset_id)
        if row is None or row["owner"] != owner:
            return None
        new_name = row["name"]
        if name is not None:
            new_name = str(name).strip()
            if not new_name:
                raise ValueError("a preset needs a name")
            new_name = new_name[:200]
        new_payload = row["payload"] if payload is None else VALIDATORS[row["kind"]](payload)
        self.db.execute(
            "UPDATE user_presets SET name=?,payload_json=?,updated_at=? WHERE preset_id=?",
            (new_name, json.dumps(new_payload), utcnow(), preset_id))
        return self.get(preset_id)

    def delete(self, preset_id: str, owner: str) -> bool:
        row = self.get(preset_id)
        if row is None or row["owner"] != owner:
            return False
        self.db.execute("DELETE FROM user_presets WHERE preset_id=?", (preset_id,))
        return True
