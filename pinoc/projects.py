"""Project model and project registry (PiNOC 2.0 Phase 1, P1-R01).

Projects are the top-level organizational object in PiNOC's environment
model: the operational unit an operator actually thinks in is a *project*
(Desk Display, MagicMirror, ADS-B, Sense, networking), each spanning
several devices and software components -- not a single device.

Design notes (spec section P1-R01):

* ``projects`` is a normalized table keyed by a stable auto-increment
  ``project_id`` plus a unique, URL-friendly ``slug``. The slug is the
  public identity used in every endpoint; nothing downstream may invent a
  second identity.
* ``project_members`` is one generic many-to-many table --
  ``(project_id, kind, object_id)`` with kind in
  :data:`MEMBER_KINDS` -- so one project relates to devices, applications,
  repositories, feeds, hardware, services, and runbooks through a single
  audited mechanism. Membership is many-to-many (an object may belong to
  several projects); removal is soft (``removed_at``) so history survives
  archiving.
* Lifecycle is ``planned / active / maintenance / retired`` plus the
  special ``archived`` state reached only through :meth:`ProjectService.
  archive`. Archiving keeps every row -- the project and all of its
  membership history remain queryable -- but removes the project from
  active summaries, and makes it **read-only**: any attempted write raises
  :class:`ProjectError` until the project is restored.
* Project metadata is not a secret store: free-text fields are length-capped
  and URLs in ``links`` must be http(s).
* Every state-changing call is audited into the existing ``audit_records``
  table through the injected ``audit`` callable (the ActionDispatcher),
  covering membership changes and criticality changes.
* Project health is a rollup of its members under the criticality policy in
  :mod:`pinoc.envstates`. Only membership kinds that have a registered
  health source contribute states; the device source is registered here,
  and later Phase 1 models (applications, feeds, repositories, ...)
  register their own through :func:`register_member_source` without
  touching this module's rollup math.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from pinoc.database import Database, utcnow
from pinoc.envstates import (
    CRITICALITIES,
    fresh_state,
    reason_code,
    rollup as _env_rollup,
    worst,
)

UTC = timezone.utc

LIFECYCLES = ("planned", "active", "maintenance", "retired", "archived")
MEMBER_KINDS = ("device", "application", "repository", "feed", "hardware", "service", "runbook")

# A member object id is a stable identifier: letters/digits plus the
# structural characters existing PiNOC ids already use.
_OBJECT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_URL_RE = re.compile(r"https?://[^\s]{1,2048}")

MAX_TAGS = 50
MAX_LINKS = 20
MAX_MEMBERS_PER_WRITE = 200


class ProjectError(ValueError):
    """Validation or lifecycle error; routes map it to 400/404/409."""


class ProjectNotFound(ProjectError):
    pass


def slugify(name: str) -> str:
    """Derive a stable slug from a project name."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")
    return slug[:64].strip("-") or "project"


def _load_json_list(raw: Any, field: str, limit: int, max_len: int) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",")]
    if not isinstance(raw, list):
        raise ProjectError(f"{field} must be a list (or comma-separated string)")
    values = [str(item).strip() for item in raw if str(item).strip()]
    if len(values) > limit:
        raise ProjectError(f"{field} may hold at most {limit} entries")
    if any(len(value) > max_len for value in values):
        raise ProjectError(f"{field} entries may be at most {max_len} characters")
    return values


def _load_links(raw: Any) -> List[Dict[str, str]]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise ProjectError("links must be a list of {label, url} objects or URLs")
    if len(raw) > MAX_LINKS:
        raise ProjectError(f"links may hold at most {MAX_LINKS} entries")
    links: List[Dict[str, str]] = []
    for entry in raw:
        if isinstance(entry, dict):
            url = str(entry.get("url") or "").strip()
            label = str(entry.get("label") or url).strip()
        else:
            url, label = str(entry).strip(), str(entry).strip()
        if not _URL_RE.fullmatch(url):
            raise ProjectError(f"link url must be an http(s) URL: {url[:80]!r}")
        links.append({"label": label[:120], "url": url})
    return links


# -- member health sources ---------------------------------------------------
#
# A *source* turns the set of a project's member object ids (of one kind)
# into per-object health entries: ``[{"object_id", "health", "reasons"}]``.
# A source must be cache/db-read only -- never a remote call -- because
# ``/health`` and every page render that rolls up projects consume it in
# request threads.
MemberSource = Callable[["ProjectService", Sequence[str]], List[Dict[str, Any]]]
RosterSource = Callable[["ProjectService"], List[str]]

_MEMBER_SOURCES: Dict[str, MemberSource] = {}
_ROSTER_SOURCES: Dict[str, RosterSource] = {}


def register_member_source(kind: str, source: MemberSource) -> None:
    """Register how one membership kind contributes health (Phase 1 models
    call this at import time; later requirements extend the rollup without
    modifying this module)."""
    if kind not in MEMBER_KINDS:
        raise ValueError(f"unknown membership kind: {kind}")
    _MEMBER_SOURCES[kind] = source


def register_roster_source(kind: str, source: RosterSource) -> None:
    """Register how one membership kind's full object roster is enumerated
    (what the unassigned-inventory view subtracts membership from)."""
    if kind not in MEMBER_KINDS:
        raise ValueError(f"unknown membership kind: {kind}")
    _ROSTER_SOURCES[kind] = source


def _device_health_source(service: "ProjectService", object_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Live device health from the shared state cache (or the persisted
    roster when no cache exists -- there is no health column on the
    devices table, so those read back as ``unknown``)."""
    if service.state is not None:
        by_id = {device["id"]: device for device in service.state.devices()}
    elif service._available():
        by_id = {}
        if object_ids:
            placeholders = ",".join("?" * len(object_ids))
            rows = service.db.rows(
                f"SELECT device_id,hostname,friendly_name FROM devices WHERE device_id IN ({placeholders})",
                tuple(object_ids))
            by_id = {row["device_id"]: row for row in rows}
    else:
        by_id = {}
    entries: List[Dict[str, Any]] = []
    for object_id in object_ids:
        device = by_id.get(object_id)
        if device is None:
            entries.append({"object_id": object_id, "health": "unknown",
                            "reasons": [reason_code("device", "unknown", object_id) + " (not in roster)"]})
            continue
        online = device.get("online")
        health = "offline" if not online else str(device.get("health") or "unknown")
        if online and device.get("stale"):
            health = "stale" if health == "healthy" else health
        entries.append({"object_id": object_id, "health": health,
                        "name": device.get("friendly_name") or device.get("hostname") or object_id,
                        "reasons": [reason_code("device", health, object_id)] if health != "healthy" else []})
    return entries


register_member_source("device", _device_health_source)
_ROSTER_SOURCES["device"] = lambda service: service.device_ids()


class ProjectService:
    """CRUD + health rollup for the projects registry.

    ``db`` is the shared history :class:`~pinoc.database.Database` (the
    service degrades to empty reads, never raises, when it is absent or
    unavailable -- the same contract every other PiNOC service keeps).
    ``state`` is the shared :class:`~pinoc.state.PiNOCState` (live device
    health for rollups) and ``audit`` is an optional
    ``ActionDispatcher.audit``-shaped callable used to record every
    state-changing operation.
    """

    def __init__(self, db: Optional[Database] = None, state: Any = None,
                 audit: Optional[Callable[..., Any]] = None) -> None:
        self.db = db
        self.state = state
        self.audit = audit

    # -- plumbing -----------------------------------------------------------
    def _available(self) -> bool:
        return self.db is not None and bool(getattr(self.db, "available", False))

    def _audit(self, actor: str, device_id: Optional[str], action: str, target: Optional[str],
               params: Dict[str, Any], result: str = "succeeded", error: Optional[str] = None) -> None:
        if self.audit is None:
            return
        try:
            self.audit(actor, "administrator", None, device_id, action, target,
                       params, "allowed", result, None, None, error)
        except Exception:  # noqa: BLE001 -- audit bookkeeping must never break the write
            pass

    def device_ids(self) -> set:
        if self.state is not None:
            return {device["id"] for device in self.state.devices() if device.get("id")}
        if self._available():
            return {row["device_id"] for row in self.db.rows("SELECT device_id FROM devices")}
        return set()

    # -- row codecs ----------------------------------------------------------
    @staticmethod
    def _decode(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            tags = json.loads(row.get("tags_json") or "[]")
            links = json.loads(row.get("links_json") or "[]")
        except (TypeError, ValueError):
            tags, links = [], []
        return {
            "id": row["slug"],
            "project_id": row["project_id"],
            "name": row["name"],
            "description": row.get("description") or "",
            "lifecycle": row["lifecycle"],
            "archived": row["lifecycle"] == "archived",
            "criticality": row.get("criticality") or "standard",
            "tags": tags,
            "owner": row.get("owner") or None,
            "links": links,
            "notes": row.get("notes") or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "archived_at": row.get("archived_at"),
            "archived_reason": row.get("archived_reason") or None,
        }

    def _fetch(self, project_id: Any) -> Optional[Dict[str, Any]]:
        if not self._available():
            return None
        key = str(project_id).strip()
        column = "project_id" if key.isdigit() else "slug"
        rows = self.db.rows(f"SELECT * FROM projects WHERE {column}=?", (key,))
        return self._decode(rows[0]) if rows else None

    def _require(self, project_id: Any) -> Dict[str, Any]:
        row = self._fetch(project_id)
        if row is None:
            raise ProjectNotFound(f"project {project_id!r} not found")
        return row

    # -- CRUD -----------------------------------------------------------------
    def list_projects(self, include_archived: bool = False,
                      lifecycle: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where, args = ["1=1"], []
        if not include_archived:
            where.append("lifecycle <> 'archived'")
        if lifecycle:
            if lifecycle not in LIFECYCLES:
                raise ProjectError(f"lifecycle must be one of {', '.join(LIFECYCLES)}")
            where.append("lifecycle = ?")
            args.append(lifecycle)
        rows = self.db.rows(
            "SELECT * FROM projects WHERE " + " AND ".join(where) + " ORDER BY name", tuple(args))
        projects = [self._decode(row) for row in rows]
        for project in projects:
            project["member_counts"] = self.member_counts(project["project_id"])
            # Per-project rollup for the card grid: state and reasons come
            # from the cache/DB only (no remote work in request threads).
            # One broken rollup degrades that card, never the whole grid.
            try:
                summary = self.health(project["project_id"])
                project["health"] = summary["health"]
                project["reasons"] = summary["reasons"]
                project["active_alert_count"] = len(summary["active_alerts"])
            except Exception:  # noqa: BLE001 -- the grid must survive any one project
                project["health"] = "unknown"
                project["reasons"] = ["health rollup failed"]
                project["active_alert_count"] = 0
        return projects

    def get(self, project_id: Any) -> Optional[Dict[str, Any]]:
        row = self._fetch(project_id)
        if row is None:
            return None
        result = dict(row)
        result["member_counts"] = self.member_counts(row["project_id"])
        result["members"] = self.members(row["project_id"])
        return result

    def create(self, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ProjectError("history database is unavailable")
        if not isinstance(payload, dict):
            raise ProjectError("payload must be an object")
        name = str(payload.get("name") or "").strip()
        if not name or len(name) > 200:
            raise ProjectError("name is required (max 200 characters)")
        slug = str(payload.get("slug") or "").strip().lower() or slugify(name)
        if not _SLUG_RE.fullmatch(slug):
            raise ProjectError("slug must be a simple lowercase identifier (letters, digits, dashes)")
        if self.db.rows("SELECT project_id FROM projects WHERE slug=?", (slug,)):
            raise ProjectError(f"slug {slug!r} is already taken")
        lifecycle = str(payload.get("lifecycle") or "planned").strip().lower()
        if lifecycle not in LIFECYCLES or lifecycle == "archived":
            raise ProjectError(f"lifecycle must be one of {', '.join(LIFECYCLES[:-1])} (archiving is an operation)")
        criticality = str(payload.get("criticality") or "standard").strip().lower()
        if criticality not in CRITICALITIES:
            raise ProjectError(f"criticality must be one of {', '.join(CRITICALITIES)}")
        description = str(payload.get("description") or "")[:2000]
        notes = str(payload.get("notes") or "")[:8000]
        owner = str(payload.get("owner") or "").strip()[:100] or None
        tags = _load_json_list(payload.get("tags"), "tags", MAX_TAGS, 100)
        links = _load_links(payload.get("links"))
        stamp = utcnow()
        project_id = self.db.execute(
            "INSERT INTO projects(slug,name,description,lifecycle,criticality,tags_json,owner,"
            "links_json,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (slug, name, description, lifecycle, criticality, json.dumps(tags), owner,
             json.dumps(links), notes, stamp, stamp))
        self._audit(actor, None, "project.create", slug,
                    {"name": name, "lifecycle": lifecycle, "criticality": criticality})
        result = self._fetch(slug)
        assert result is not None
        result["member_counts"] = self.member_counts(result["project_id"])
        return result

    def update(self, project_id: Any, payload: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        if not self._available():
            raise ProjectError("history database is unavailable")
        current = self._require(project_id)
        if current["lifecycle"] == "archived":
            raise ProjectError("project is archived and read-only; restore it before editing")
        if not isinstance(payload, dict):
            raise ProjectError("payload must be an object")
        fields: List[str] = []
        values: Dict[str, Any] = {}
        if "name" in payload:
            name = str(payload["name"] or "").strip()
            if not name or len(name) > 200:
                raise ProjectError("name must be 1-200 characters")
            fields.append("name=?")
            values["name"] = name
        if "description" in payload:
            fields.append("description=?")
            values["description"] = str(payload["description"] or "")[:2000]
        if "notes" in payload:
            fields.append("notes=?")
            values["notes"] = str(payload["notes"] or "")[:8000]
        if "owner" in payload:
            fields.append("owner=?")
            values["owner"] = str(payload["owner"] or "").strip()[:100] or None
        if "tags" in payload:
            fields.append("tags_json=?")
            values["tags_json"] = json.dumps(_load_json_list(payload["tags"], "tags", MAX_TAGS, 100))
        if "links" in payload:
            fields.append("links_json=?")
            values["links_json"] = json.dumps(_load_links(payload["links"]))
        if "criticality" in payload:
            criticality = str(payload["criticality"] or "").strip().lower()
            if criticality not in CRITICALITIES:
                raise ProjectError(f"criticality must be one of {', '.join(CRITICALITIES)}")
            if criticality != current["criticality"]:
                self._audit(actor, None, "project.criticality", current["id"],
                            {"old": current["criticality"], "new": criticality})
            fields.append("criticality=?")
            values["criticality"] = criticality
        if "lifecycle" in payload:
            lifecycle = str(payload["lifecycle"] or "").strip().lower()
            if lifecycle not in LIFECYCLES or lifecycle == "archived":
                raise ProjectError("lifecycle must be one of planned, active, maintenance, or retired "
                                   "(archiving/restoring is an operation)")
            if lifecycle != current["lifecycle"]:
                self._audit(actor, None, "project.lifecycle", current["id"],
                            {"old": current["lifecycle"], "new": lifecycle})
            fields.append("lifecycle=?")
            values["lifecycle"] = lifecycle
        if not fields:
            return current
        self.db.execute(
            f"UPDATE projects SET {', '.join(fields)},updated_at=? WHERE project_id=?",
            (*values.values(), utcnow(), current["project_id"]))
        self._audit(actor, None, "project.update", current["id"], dict(values))
        return self._require(project_id)

    def archive(self, project_id: Any, actor: str = "system", reason: str = "") -> Dict[str, Any]:
        current = self._require(project_id)
        if current["lifecycle"] == "archived":
            return current
        self.db.execute(
            "UPDATE projects SET lifecycle='archived',archived_at=?,archived_reason=?,updated_at=? "
            "WHERE project_id=?",
            (utcnow(), str(reason or "")[:500], utcnow(), current["project_id"]))
        self._audit(actor, None, "project.archive", current["id"],
                    {"previous_lifecycle": current["lifecycle"], "reason": str(reason or "")[:500]})
        return self._require(project_id)

    def restore(self, project_id: Any, actor: str = "system") -> Dict[str, Any]:
        current = self._require(project_id)
        if current["lifecycle"] != "archived":
            raise ProjectError("only archived projects can be restored")
        self.db.execute(
            "UPDATE projects SET lifecycle='retired',archived_at=NULL,archived_reason=NULL,updated_at=? "
            "WHERE project_id=?", (utcnow(), current["project_id"]))
        self._audit(actor, None, "project.restore", current["id"], {})
        return self._require(project_id)

    # -- membership ------------------------------------------------------------
    def _member_rows(self, project_id: int, include_removed: bool = False) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where = "project_id=?" + ("" if include_removed else " AND removed_at IS NULL")
        return self.db.rows(f"SELECT * FROM project_members WHERE {where} ORDER BY kind,object_id",
                            (project_id,))

    def members(self, project_id: Any, include_removed: bool = False) -> Dict[str, List[str]]:
        current = self._require(project_id)
        grouped: Dict[str, List[str]] = {kind: [] for kind in MEMBER_KINDS}
        for row in self._member_rows(current["project_id"], include_removed):
            if row["kind"] in grouped:
                grouped[row["kind"]].append(row["object_id"])
        return {kind: ids for kind, ids in grouped.items() if ids or include_removed}

    def member_counts(self, project_id: Any) -> Dict[str, int]:
        """Per-kind active member counts; accepts a slug or an integer id."""
        if not self._available():
            return {}
        key = str(project_id).strip()
        column = "project_id" if key.isdigit() else "slug"
        rows = self.db.rows(
            "SELECT kind,COUNT(*) AS count FROM project_members WHERE removed_at IS NULL AND "
            f"project_id=(SELECT project_id FROM projects WHERE {column}=?) GROUP BY kind",
            (key,))
        return {row["kind"]: row["count"] for row in rows}

    def add_members(self, project_id: Any, kind: str, object_ids: Iterable[str],
                    actor: str = "system") -> Dict[str, Any]:
        current = self._require(project_id)
        if current["lifecycle"] == "archived":
            raise ProjectError("project is archived and read-only; restore it before changing membership")
        if kind not in MEMBER_KINDS:
            raise ProjectError(f"kind must be one of {', '.join(MEMBER_KINDS)}")
        ids = _load_json_list(list(object_ids), "object_ids", MAX_MEMBERS_PER_WRITE, 256)
        if not ids:
            raise ProjectError("object_ids must be a non-empty list")
        if any(not _OBJECT_ID_RE.fullmatch(item) for item in ids):
            raise ProjectError("object_ids must be simple stable identifiers")
        if kind == "device":
            known = self.device_ids()
            if known:
                unknown = [item for item in ids if item not in known]
                if unknown:
                    raise ProjectError(f"unknown device(s): {', '.join(unknown[:5])}")
        stamp = utcnow()
        added: List[str] = []
        for item in sorted(set(ids)):
            existing = self.db.rows(
                "SELECT removed_at FROM project_members WHERE project_id=? AND kind=? AND object_id=?",
                (current["project_id"], kind, item))
            if existing:
                if existing[0]["removed_at"] is None:
                    continue
                self.db.execute(
                    "UPDATE project_members SET removed_at=NULL,added_at=?,added_by=? "
                    "WHERE project_id=? AND kind=? AND object_id=?",
                    (stamp, actor, current["project_id"], kind, item))
            else:
                self.db.execute(
                    "INSERT INTO project_members(project_id,kind,object_id,added_by,added_at,removed_at) "
                    "VALUES(?,?,?,?,?,NULL)",
                    (current["project_id"], kind, item, actor, stamp))
            added.append(item)
        if added:
            self._audit(actor, None, "project.members.add", current["id"], {"kind": kind, "added": added})
        return {"id": current["id"], "kind": kind, "added": added}

    def remove_members(self, project_id: Any, kind: str, object_ids: Iterable[str],
                       actor: str = "system") -> Dict[str, Any]:
        current = self._require(project_id)
        if current["lifecycle"] == "archived":
            raise ProjectError("project is archived and read-only; restore it before changing membership")
        if kind not in MEMBER_KINDS:
            raise ProjectError(f"kind must be one of {', '.join(MEMBER_KINDS)}")
        ids = _load_json_list(list(object_ids), "object_ids", MAX_MEMBERS_PER_WRITE, 256)
        if not ids:
            raise ProjectError("object_ids must be a non-empty list")
        stamp = utcnow()
        removed: List[str] = []
        for item in sorted(set(ids)):
            # Database.execute() returns lastrowid (None for UPDATEs), so
            # the existence of an active row is checked before the write.
            existing = self.db.rows(
                "SELECT 1 FROM project_members WHERE project_id=? AND kind=? AND object_id=? "
                "AND removed_at IS NULL",
                (current["project_id"], kind, item))
            if existing:
                self.db.execute(
                    "UPDATE project_members SET removed_at=? WHERE project_id=? AND kind=? "
                    "AND object_id=? AND removed_at IS NULL",
                    (stamp, current["project_id"], kind, item))
                removed.append(item)
        if removed:
            self._audit(actor, None, "project.members.remove", current["id"], {"kind": kind, "removed": removed})
        return {"id": current["id"], "kind": kind, "removed": removed}

    # -- unassigned inventory -----------------------------------------------------
    def unassigned(self, kind: str = "device") -> Dict[str, Any]:
        """Objects of ``kind`` that belong to no *active* (non-archived)
        project. For kinds whose roster is not yet known (their Phase 1
        model may not exist in this checkout) this returns the assigned
        inventory with an empty unassigned set, never an error."""
        if kind not in MEMBER_KINDS:
            raise ProjectError(f"kind must be one of {', '.join(MEMBER_KINDS)}")
        source = _ROSTER_SOURCES.get(kind)
        roster = source(self) if source is not None else []
        if not self._available():
            return {"kind": kind, "unassigned": sorted(roster), "assigned": []}
        rows = self.db.rows(
            "SELECT DISTINCT object_id FROM project_members WHERE kind=? AND removed_at IS NULL "
            "AND project_id IN (SELECT project_id FROM projects WHERE lifecycle <> 'archived')",
            (kind,))
        assigned = {row["object_id"] for row in rows}
        return {"kind": kind, "assigned": sorted(assigned),
                "unassigned": sorted(set(roster) - assigned)}

    # -- health rollup ---------------------------------------------------------------
    def health(self, project_id: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
        current = self._require(project_id)
        members = self.members(current["project_id"])
        per_kind: Dict[str, List[Dict[str, Any]]] = {}
        member_tuples: List[Tuple[str, str, str]] = []
        for kind, ids in members.items():
            if not ids:
                continue
            source = _MEMBER_SOURCES.get(kind)
            entries = source(self, ids) if source is not None else [
                {"object_id": item, "health": "unknown", "reasons": []} for item in ids]
            per_kind[kind] = entries
            member_tuples.extend((entry.get("object_id") or item, kind, entry.get("health") or "unknown")
                                 for entry, item in zip(entries, ids))
        state, reasons = _env_rollup(member_tuples, current["criticality"])
        if current["lifecycle"] == "archived":
            state = "maintenance"
            reasons = ["archived project (read-only)"]
        elif current["lifecycle"] == "retired":
            state = worst(state, "maintenance")
        # Active alerts on member devices, for the card's "needs attention"
        # strip -- read from the durable alerts table, never re-collected.
        alerts: List[Dict[str, Any]] = []
        device_members = members.get("device") or []
        if device_members and self._available():
            placeholders = ",".join("?" * len(device_members))
            alerts = self.db.rows(
                "SELECT alert_id,device_id,alert_type,severity,message,opened_at,last_seen_at FROM alerts "
                f"WHERE resolved_at IS NULL AND device_id IN ({placeholders}) "
                "ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'degraded' THEN 2 "
                "WHEN 'warning' THEN 1 ELSE 0 END DESC, last_seen_at DESC LIMIT 25",
                tuple(device_members))
        return {
            "id": current["id"],
            "name": current["name"],
            "lifecycle": current["lifecycle"],
            "criticality": current["criticality"],
            "health": state,
            "reasons": reasons,
            "members": per_kind,
            "active_alerts": alerts,
            "generated_at": (now or datetime.now(UTC)).isoformat(),
        }

    def project_summaries(self) -> List[Dict[str, Any]]:
        """One rollup per active project -- the card grid's data source."""
        if not self._available():
            return []
        rows = self.db.rows("SELECT * FROM projects WHERE lifecycle <> 'archived' ORDER BY name")
        summaries = []
        for row in rows:
            try:
                summaries.append(self.health(row["slug"]))
            except Exception:  # noqa: BLE001 -- one bad project never breaks the grid
                summaries.append({"id": row["slug"], "name": row["name"], "lifecycle": row["lifecycle"],
                                  "criticality": row.get("criticality") or "standard",
                                  "health": "unknown", "reasons": ["rollup failed"],
                                  "members": {}, "active_alerts": [],
                                  "generated_at": utcnow()})
        return summaries

    # -- graph -----------------------------------------------------------------------
    def graph(self, project_id: Any) -> Dict[str, Any]:
        """The project with its full membership graph, for the detail view:
        every member of every kind, each with its health and (for devices)
        its live services/integrations from the state cache -- the
        project → application → instance → device → service/feed/repo
        drill-down spine of the Phase 1 console."""
        current = self.get(project_id)
        if current is None:
            raise ProjectNotFound(f"project {project_id!r} not found")
        health = self.health(current["id"])
        device_cache: Dict[str, Any] = {}
        if self.state is not None:
            device_cache = {device["id"]: device for device in self.state.devices()}
        graph_members: Dict[str, List[Dict[str, Any]]] = {}
        for kind, entries in health["members"].items():
            enriched = []
            for entry in entries:
                item = dict(entry)
                if kind == "device":
                    device = device_cache.get(entry["object_id"]) or {}
                    item["online"] = bool(device.get("online"))
                    item["services"] = [service.get("name") for service in device.get("services", [])
                                        if service.get("name")][:40]
                    item["integrations"] = sorted((device.get("integrations") or {}).keys())
                enriched.append(item)
            graph_members[kind] = enriched
        return {"project": {key: value for key, value in current.items() if key != "members"},
                "health": {key: value for key, value in health.items() if key != "members"},
                "members": graph_members}
