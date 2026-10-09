"""Fleet software and version inventory (PiNOC 2.0 Phase 1, P1-R04).

A *software component* is one versioned thing on one device -- the
operating system, kernel, architecture, a runtime (python3, node, npm,
git), the package manager's aggregate update state, the PiNOC agent, or an
application's version. The purpose is to make the repeated manual checks
("what Python is on that box? which packages need updating? what PiNOC
version is running where?") one query instead of one SSH session each.

Design notes (spec section P1-R04):

* Every monitored device gets a software posture record: one row in
  ``software_components`` per (device, application, name, kind). The raw
  version is retained for display next to a normalized comparison form
  (case-folded, ``v``-prefix stripped), so ``v1.2.3`` and ``1.2.3`` compare
  equal while each source's spelling survives in the UI.
* Component state is one of ``current / update_available / security_update /
  stale / unknown`` -- the spec's distinguished conditions. The *concrete*
  state is derived from the last observed facts (a component with a learned
  version is current; the package component's apt counts make it
  update_available, or security_update when any of the pending updates is
  security-critical); *stale* is the freshness overlay: once the last
  observation is older than ``software.stale_seconds`` the component reports
  stale while its last concrete state is preserved in the reasons -- a
  failed collection never erases the last success. ``unknown`` is a
  component that is known (the host reported it) but whose version no
  source has ever learned (a host without the tool reports "unknown").
* Observations arrive through a background refresh thread that performs
  **local reads only** (the phase architecture invariant: no remote work in
  request threads, and no *new* remote work at all -- the underlying data
  flows through existing channels): the live device state's OS/kernel/
  architecture, the fleet collector's due-gated ``__RUNTIMES__`` section
  (the one new bounded read this requirement adds, on its own low-frequency
  cadence), the ``packages`` integration's apt counts, the ``agents``
  table, and the ``applications``/``application_instances`` tables. Per
  component the newest observation wins, freshness timestamps only move
  forward, and a source that stops reporting (a host going offline) ages
  the row to *stale* instead of erasing it.
* Version changes and state transitions generate events through the
  general history ``events`` log (its retention already applies); this
  service never writes anywhere else, and Phase 1 is read-only toward the
  devices themselves -- there is no operator CRUD and no package
  credentials, and the only remote work ever performed is the existing,
  already-bounded fleet poll.
* The on-demand side of the spec ("on-demand inventory is a bounded job")
  is met by the bounded background tick (per-scan row caps, per-entry
  length caps, one bounded runtimes section per cadence): the API and the
  console read the durable records and age them -- "reachable but stale"
  is a first-class answer, never a live SSH in a page render.

Every output passes through the security layer's recursive ``redact()``
before it leaves the process, the same contract the repository and
application services keep.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pinoc.database import Database, utcnow
from pinoc.envstates import age_seconds, parse_ts, reason_code

LOG = logging.getLogger("pinoc.software")
UTC = timezone.utc

# The kinds of software tracked on a device (spec scope list).
KINDS = ("os", "kernel", "architecture", "runtime", "package", "agent", "application")

# The five states the spec requires to be distinguishable, in *ascending*
# severity rank: current (no problem) < unknown (never learned) < stale
# (information may be out of date) < update_available < security_update
# (the most actionable condition). The worst of a device's components is
# its software posture.
SOFTWARE_STATES = ("current", "unknown", "stale", "update_available", "security_update")
_STATE_RANK = {state: rank for rank, state in enumerate(SOFTWARE_STATES)}
# Event severity for a state transition into one of the states above.
_STATE_SEVERITY = {
    "current": "info", "unknown": "info", "stale": "info",
    "update_available": "warning", "security_update": "warning",
}

# Observation sources (see the module docstring for where each one's data
# already comes from); the newest observation wins per field.
SOURCES = ("device_state", "fleet_runtimes", "packages_integration", "agents", "applications")

# Bounds -- registry entries are capped like every other PiNOC registry.
MAX_NAME = 128
MAX_VERSION = 128
MAX_SOURCE = 64
MAX_SCAN_ROWS = 5000  # per-tick bound on the agents/applications scans


class SoftwareError(ValueError):
    """Validation or filter error; routes map it to 400/404."""


class SoftwareNotFound(SoftwareError):
    pass


def normalize_version(value: Any) -> str:
    """The normalized comparison form of a version string.

    Surrounding whitespace is trimmed, a leading ``v``/``V`` is stripped,
    and case is folded, so ``v1.2.3``/``V1.2.3``/``1.2.3`` all normalize
    the same way while the *raw* value is preserved separately for display
    (spec: "retain raw version plus normalized comparison"). ``unknown``
    (the fleet's "tool not installed" sentinel) and empty strings stay
    exactly what they are -- callers treat them as "no version learned".
    """
    text = str(value or "").strip()
    if text[:1] in ("v", "V") and len(text) > 1:
        text = text[1:]
    return text.lower()


def _loads_list(raw: Any) -> List[Any]:
    if raw is None:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def _ts_value(value: Any, now: datetime) -> float:
    """A timestamp as a comparable float (epoch seconds); missing or
    unparseable values sort as the oldest possible."""
    parsed = parse_ts(value) if value else None
    if parsed is None:
        return 0.0
    return parsed.timestamp()


def _bounded_int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if -100000 <= number < 100000 else None


def _component_ref(row: Dict[str, Any]) -> str:
    """A stable, readable identifier for one component, used in reason
    codes and event messages (device + component; the application slug
    disambiguates application components)."""
    name = row.get("name") or "?"
    application = row.get("application_slug")
    return f"{row.get('device_id') or '?'}:{name}" + (f" ({application})" if application else "")


class SoftwareService:
    """Fleet software and version inventory.

    ``db`` is the shared history :class:`~pinoc.database.Database` (the
    service degrades to empty reads, never raises, when it is absent or
    unavailable -- the same contract every other PiNOC service keeps);
    ``state`` is the shared :class:`~pinoc.state.PiNOCState` (live device
    state: OS/kernel/architecture and the ``runtimes`` list); ``history``
    is the HistoryManager (version-change and state-transition events go
    through its general events log); ``config`` is the top-level
    ``software`` configuration section; ``audit`` and ``redact`` keep the
    constructor shape every other PiNOC service exposes (Phase 1 performs
    no operator writes, so the audit callable is only ever None or unused).
    """

    def __init__(self, db: Optional[Database] = None, state: Any = None,
                 history: Any = None, config: Optional[Dict[str, Any]] = None,
                 audit: Optional[Callable[..., Any]] = None,
                 redact: Optional[Callable[[Any], Any]] = None) -> None:
        cfg = config or {}
        self.db = db
        self.state = state
        self.history = history
        self.audit = audit
        self.redact = redact if redact is not None else (lambda value: value)
        self.enabled = bool(cfg.get("enabled", True))
        self.refresh_seconds = max(30.0, float(cfg.get("refresh_seconds", 300)))
        self.stale_seconds = max(60.0, float(cfg.get("stale_seconds", 86400)))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-software", daemon=True)

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self.enabled and self.db is not None:
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
                LOG.exception("software inventory refresh failed")
            self.stop_event.wait(self.refresh_seconds)

    # -- plumbing -------------------------------------------------------------
    def _available(self) -> bool:
        return self.db is not None and bool(getattr(self.db, "available", False))

    def _devices(self) -> Dict[str, Dict[str, Any]]:
        if self.state is None:
            return {}
        return {device["id"]: device for device in self.state.devices() if device.get("id")}

    def _device_info(self) -> Dict[str, Dict[str, Any]]:
        devices = self._devices()
        if devices:
            return {device_id: {"id": device_id,
                                "hostname": device.get("hostname"),
                                "friendly_name": device.get("friendly_name"),
                                "online": bool(device.get("online"))}
                    for device_id, device in devices.items()}
        if self._available():
            return {row["device_id"]: {"id": row["device_id"], "hostname": row.get("hostname"),
                                       "friendly_name": row.get("friendly_name"),
                                       "online": False}
                    for row in self.db.rows("SELECT device_id,hostname,friendly_name FROM devices")}
        return {}

    def _emit(self, device_id: Optional[str], event_type: str, severity: str,
              message: str, metadata: Dict[str, Any]) -> None:
        """Record one event through the general history events log.

        The events table already has its own retention (history
        maintenance), so this service deliberately does not add a parallel
        software event table of its own. Enqueue failures must never break
        the refresh loop, hence the broad catch.
        """
        if self.history is None:
            return
        try:
            self.history.event(device_id, event_type, severity, message, metadata)
        except Exception:
            LOG.warning("software event enqueue failed (%s)", event_type)

    # -- row codec -----------------------------------------------------------
    def _decode_component(self, row: Dict[str, Any]) -> Dict[str, Any]:
        version = row.get("version")
        return {
            "id": row["component_id"],
            "component_id": row["component_id"],
            "device_id": row["device_id"],
            "application": row.get("application_slug"),
            "name": row["name"],
            "kind": row.get("kind") or "unknown",
            "version": version,
            "normalized_version": row.get("normalized_version") or normalize_version(version) or None,
            "pending_updates": row.get("pending_updates"),
            "security_updates": row.get("security_updates"),
            "source": row.get("source"),
            "confidence": row.get("confidence"),
            "state": row.get("state") or "unknown",
            "state_reasons": _loads_list(row.get("state_reasons_json")),
            "observed_at": row.get("observed_at"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    # -- read API -------------------------------------------------------------
    def _filter_clause(self, device: Optional[str], name: Optional[str],
                       kind: Optional[str], application: Optional[str],
                       project: Optional[str], state: Optional[str]) -> Tuple[str, List[Any]]:
        where, args = ["1=1"], []
        if device:
            where.append("device_id=?")
            args.append(str(device).strip())
        if name:
            where.append("name LIKE ?")
            args.append(f"%{str(name).strip()}%")
        if kind:
            if kind not in KINDS:
                raise SoftwareError(f"kind must be one of {', '.join(KINDS)}")
            where.append("kind=?")
            args.append(kind)
        if application:
            where.append("application_slug=?")
            args.append(str(application).strip().lower())
        if project:
            # Group by project: a component belongs to a project through its
            # device's membership (a device in the project means the device's
            # whole software posture is the project's).
            where.append(
                "device_id IN (SELECT object_id FROM project_members WHERE kind='device' "
                "AND removed_at IS NULL AND project_id="
                "(SELECT project_id FROM projects WHERE slug=?))")
            args.append(str(project).strip())
        if state:
            if state not in SOFTWARE_STATES:
                raise SoftwareError(f"state must be one of {', '.join(SOFTWARE_STATES)}")
            where.append("state=?")
            args.append(state)
        return " AND ".join(where), args

    def _query(self, device: Optional[str] = None, name: Optional[str] = None,
               kind: Optional[str] = None, application: Optional[str] = None,
               project: Optional[str] = None, state: Optional[str] = None,
               limit: int = 5000) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where, args = self._filter_clause(device, name, kind, application, project, state)
        rows = self.db.rows(
            "SELECT * FROM software_components WHERE " + where +
            " ORDER BY device_id,name,kind LIMIT ?", args + [int(limit)])
        components = [self._decode_component(row) for row in rows]
        devices = self._device_info()
        for component in components:
            component["device"] = devices.get(component["device_id"])
        return components

    def list(self, device: Optional[str] = None, name: Optional[str] = None,
             kind: Optional[str] = None, application: Optional[str] = None,
             project: Optional[str] = None, state: Optional[str] = None) -> List[Dict[str, Any]]:
        """The software inventory, filtered like every other fleet view.

        Returns components worst-state-first so the queue an operator
        actually cares about (security updates, then other updates, then
        stale) sorts to the top within each device.
        """
        components = self._query(device=device, name=name, kind=kind,
                                 application=application, project=project, state=state)
        components.sort(key=lambda c: (
            c["device_id"] or "", c["name"] or "", c["kind"] or "",
            -_STATE_RANK.get(c["state"], 0)))
        return components

    def device_software(self, device_id: Any) -> Optional[Dict[str, Any]]:
        """One device's software posture (GET /devices/{id}/software): all of
        the device's components plus its worst rollup state."""
        if not self._available():
            return None
        key = str(device_id).strip()
        rows = self.db.rows("SELECT * FROM software_components WHERE device_id=? ORDER BY name,kind", (key,))
        if not rows and not self._device_info().get(key):
            return None
        components = [self._decode_component(row) for row in rows]
        devices = self._device_info()
        for component in components:
            component["device"] = devices.get(key)
        counts: Dict[str, int] = {}
        for component in components:
            counts[component["state"]] = counts.get(component["state"], 0) + 1
        rollup = (max((c["state"] for c in components), key=lambda s: _STATE_RANK.get(s, 0))
                  if components else "unknown")
        summary = ", ".join(f"{counts[s]} {s}" for s in ("security_update", "update_available", "stale", "unknown", "current") if counts.get(s))
        return {
            "device": devices.get(key) or {"id": key},
            "state": rollup,
            "component_count": len(components),
            "state_counts": counts,
            "state_reasons": [f"{len(components)} component(s): {summary}"] if components else [],
            "components": components,
        }

    def updates(self, device: Optional[str] = None, name: Optional[str] = None,
                kind: Optional[str] = None, application: Optional[str] = None,
                project: Optional[str] = None) -> Dict[str, Any]:
        """Available updates, split the way the spec requires: the
        security-critical queue is separate from the general update queue.

        The split is computed from the package component's *last known
        counts* (not its current state), so a package row whose observation
        has aged to *stale* still appears in the queue it was last known to
        belong to -- the state column and reasons then tell the operator the
        information may be out of date.
        """
        components = self._query(device=device, name=name, kind=kind,
                                 application=application, project=project)
        security: List[Dict[str, Any]] = []
        available: List[Dict[str, Any]] = []
        for component in components:
            if component["kind"] != "package":
                continue
            if (component.get("security_updates") or 0) > 0:
                security.append(component)
            elif (component.get("pending_updates") or 0) > 0:
                available.append(component)
        def sort_key(component: Dict[str, Any]) -> Tuple[str, int, str]:
            return (component["device_id"] or "",
                    -(component.get("security_updates") or component.get("pending_updates") or 0),
                    component["state"])
        security.sort(key=sort_key)
        available.sort(key=sort_key)
        return {
            "security": security,
            "available": available,
            "security_count": len(security),
            "available_count": len(available),
        }

    def export(self, device: Optional[str] = None, name: Optional[str] = None,
               kind: Optional[str] = None, application: Optional[str] = None,
               project: Optional[str] = None, state: Optional[str] = None) -> Dict[str, Any]:
        """The current inventory as flat rows honoring the active filters
        (spec: "export matches current filters"). The web layer renders
        these as CSV or JSON."""
        components = self._query(device=device, name=name, kind=kind,
                                 application=application, project=project, state=state)
        rows = [{
            "device": (c.get("device") or {}).get("friendly_name") or c.get("device_id") or "",
            "device_id": c.get("device_id") or "",
            "application": c.get("application") or "",
            "component": c.get("name") or "",
            "kind": c.get("kind") or "",
            "version": c.get("version") or "",
            "normalized_version": c.get("normalized_version") or "",
            "pending_updates": c.get("pending_updates") or "",
            "security_updates": c.get("security_updates") or "",
            "state": c.get("state") or "",
            "source": c.get("source") or "",
            "observed_at": c.get("observed_at") or "",
        } for c in components]
        return {
            "columns": ["device", "device_id", "application", "component", "kind",
                        "version", "normalized_version", "pending_updates",
                        "security_updates", "state", "source", "observed_at"],
            "rows": rows,
        }

    # -- source refresh (background thread only; local reads) -------------------
    def tick(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """One source refresh + full state re-derivation. Called by the
        background thread on ``refresh_seconds`` cadence and by tests
        directly; it is all local reads plus this service's own table."""
        if not self._available():
            return {"status": "unavailable"}
        now = now or datetime.now(UTC)
        stamp = now.isoformat()
        observations = self._collect_observations(now)
        applied = 0
        for (device_id, application, name, kind), obs in sorted(observations.items(), key=str):
            try:
                self._apply_observation((device_id, application, name, kind), obs, now, stamp)
                applied += 1
            except Exception:
                LOG.exception("software observation failed (%s)", (device_id, name, kind))
        self._ensure_posture_rows(now, stamp)
        state_changes = self._rederive_states(now, stamp)
        return {"status": "ok", "observations": len(observations),
                "applied": applied, "state_changes": state_changes}

    def _collect_observations(self, now: datetime) -> Dict[Tuple[str, Optional[str], str, str], Dict[str, Any]]:
        """Merge every local source into per-component observations.

        All inputs are local reads: the in-memory device state (OS, kernel,
        architecture, runtimes), the ``packages`` integration entry the
        fleet already carries, and the agents/applications tables the agent
        and application services already maintain -- the remote work was
        done by the fleet poll and the agent long ago.
        """
        observations: Dict[Tuple[str, Optional[str], str, str], Dict[str, Any]] = {}

        def add(device_id: Optional[str], application: Optional[str], name: str, kind: str,
                source: str, observed_at: Any, version: Any = None,
                pending_updates: Any = None, security_updates: Any = None) -> None:
            if not device_id or not name or not kind:
                return
            key = (str(device_id), application, str(name)[:MAX_NAME], str(kind)[:16])
            raw_version = str(version)[:MAX_VERSION] if version is not None else None
            obs: Dict[str, Any] = {"source": source,
                                   "observed_at": str(observed_at).strip() if observed_at else ""}
            if raw_version is not None:
                obs["version"] = raw_version
                obs["normalized_version"] = normalize_version(raw_version)
            if pending_updates is not None:
                obs["pending_updates"] = _bounded_int(pending_updates)
            if security_updates is not None:
                obs["security_updates"] = _bounded_int(security_updates)
            obs["_ts"] = _ts_value(obs["observed_at"], now)
            existing = observations.get(key)
            if existing is None:
                observations[key] = obs
                return
            # Newest observation wins per field; on ties a field the
            # incumbent already knows keeps its value.
            if obs["_ts"] > existing["_ts"]:
                existing.update(obs)
            elif obs["_ts"] == existing["_ts"]:
                for field, value in obs.items():
                    if field != "source" and existing.get(field) is None:
                        existing[field] = value

        # One bounded scan of the tables whose rows are per-device.
        agents: Dict[str, Dict[str, Any]] = {}
        if self._available():
            for row in self.db.rows(
                    "SELECT device_id,agent_version,last_seen FROM agents "
                    "WHERE enabled=1 AND credential_revoked=0 "
                    f"ORDER BY last_seen DESC LIMIT {MAX_SCAN_ROWS}"):
                current = agents.get(row["device_id"])
                if current is None or (row.get("last_seen") or "") >= (current.get("last_seen") or ""):
                    agents[row["device_id"]] = row
        applications: Dict[str, List[Dict[str, Any]]] = {}
        if self._available():
            for row in self.db.rows(
                    "SELECT i.device_id,a.slug,a.name,a.version,"
                    "a.updated_at AS app_updated_at,i.updated_at AS instance_updated_at "
                    "FROM application_instances i JOIN applications a ON a.slug=i.app_slug "
                    "WHERE i.enabled=1 AND a.lifecycle<>'archived' "
                    f"LIMIT {MAX_SCAN_ROWS}"):
                applications.setdefault(row["device_id"], []).append(row)

        for device_id, device in self._devices().items():
            # The device's last *successful* collection: on a failed poll the
            # fleet carries the previous snapshot forward and last_seen is
            # unchanged, so this timestamp only ever moves forward.
            observed_at = device.get("last_successful_collection") or device.get("last_seen") or now.isoformat()
            # Fixed component name (matching the posture placeholder below); the
            # distribution and its release travel together as the version
            # ("Raspbian 12") so one observed value keeps both facts.
            os_name = str(device.get("os") or "").strip()
            os_version = str(device.get("os_version") or "").strip()
            os_version = f"{os_name} {os_version}".strip()
            if os_version:
                add(device_id, None, "operating system", "os",
                    "device_state", observed_at, version=os_version)
            kernel = str(device.get("kernel") or "").strip() or None
            if kernel:
                add(device_id, None, "kernel", "kernel", "device_state", observed_at, version=kernel)
            architecture = str(device.get("architecture") or "").strip() or None
            if architecture:
                add(device_id, None, "architecture", "architecture",
                    "device_state", observed_at, version=architecture)
            for entry in device.get("runtimes") or []:
                if not isinstance(entry, dict):
                    continue
                add(device_id, None, str(entry.get("name") or ""), "runtime",
                    "fleet_runtimes", observed_at, version=entry.get("version"))
            packages = (device.get("integrations") or {}).get("packages")
            if isinstance(packages, dict) and packages.get("available"):
                data = packages.get("data") or {}
                add(device_id, None, "packages", "package", "packages_integration",
                    packages.get("last_success") or packages.get("last_attempt") or observed_at,
                    pending_updates=data.get("updates_available"),
                    security_updates=data.get("security_updates"))
            agent = agents.get(device_id)
            if agent and agent.get("agent_version"):
                add(device_id, None, "pi_noc_agent", "agent", "agents",
                    agent.get("last_seen") or observed_at, version=agent["agent_version"])
            for row in applications.get(device_id) or []:
                add(device_id, row["slug"], row.get("name") or row["slug"], "application",
                    "applications",
                    row.get("app_updated_at") or row.get("instance_updated_at") or observed_at,
                    version=row.get("version"))
        return observations

    def _ensure_posture_rows(self, now: datetime, stamp: str) -> None:
        """Give every monitored device a posture record (spec: "every
        monitored device has a software posture record"). A device the live
        state carries but which no source has ever reported a component for
        gets one honest ``unknown`` placeholder ("operating system", no
        version learned) -- explicitly *shown* as unknown per the spec,
        never silently absent. Once a source reports the OS, the normal
        upsert key finds the same row and fills it in; nothing is ever
        deleted, so a later-discovered device keeps its history."""
        if not self._available() or not self._devices():
            return
        for device_id, device in self._devices().items():
            if self.db.rows(
                    "SELECT component_id FROM software_components WHERE device_id=?",
                    (device_id,)):
                continue
            observed_at = (device.get("last_successful_collection")
                           or device.get("last_seen") or now.isoformat())
            try:
                self.db.execute(
                    "INSERT INTO software_components(device_id,application_slug,name,kind,"
                    "version,normalized_version,pending_updates,security_updates,source,"
                    "confidence,state,state_reasons_json,observed_at,created_at,updated_at) "
                    "VALUES(?,NULL,?,?,NULL,NULL,NULL,NULL,?,1.0,'unknown','[]',?,?,?)",
                    (device_id, "operating system", "os", "device_state",
                     observed_at, stamp, stamp))
            except Exception:
                LOG.exception("could not create posture record for device %s", device_id)

    def _apply_observation(self, key: Tuple[str, Optional[str], str, str],
                           obs: Dict[str, Any], now: datetime, stamp: str) -> None:
        """Upsert one component from one merged observation. Freshness
        timestamps only move forward and learned version facts are only
        ever replaced by *newer* observations -- an old source can confirm
        a component still exists (observed_at) but cannot rewind its
        version or clear learned counts."""
        device_id, application, name, kind = key
        # SQLite treats NULLs as distinct in a UNIQUE constraint, so the
        # upsert key match uses IS (which behaves like = for non-NULL and
        # IS NULL for NULL) instead of =.
        existing = self.db.rows(
            "SELECT * FROM software_components WHERE device_id=? AND name=? AND kind=? "
            "AND application_slug IS ?", (device_id, name, kind, application))
        observed_at = obs.get("observed_at") or stamp
        observed_ts = obs.get("_ts") or _ts_value(observed_at, now)
        source = obs.get("source") or "device_state"
        version = obs.get("version")
        normalized = obs.get("normalized_version")
        if version is not None:
            normalized = normalize_version(version)
        has_version = version is not None and normalize_version(version) not in ("", "unknown")
        pending = obs.get("pending_updates")
        security = obs.get("security_updates")
        if existing:
            row = existing[0]
            fields: List[str] = []
            values: List[Any] = []
            stored_observed_ts = _ts_value(row.get("observed_at"), now)
            if observed_ts > stored_observed_ts:
                fields.append("observed_at=?")
                values.append(observed_at)
            if observed_ts >= stored_observed_ts and observed_ts > 0:
                fields.append("source=?")
                values.append(source[:MAX_SOURCE])
            if has_version and observed_ts >= stored_observed_ts and observed_ts > 0:
                # Compare the normalized forms: two sources may spell one
                # version differently (v1.2.3 vs 1.2.3) without that being
                # a version *change* worth an event.
                if normalize_version(row.get("version")) != normalize_version(version):
                    self._emit(device_id, "software_version_changed", "info",
                               f"{name} version changed {row.get('version') or 'unknown'} -> {version}",
                               {"component": name, "kind": kind, "application": application,
                                "old_version": row.get("version"), "new_version": version,
                                "source": source})
                fields.append("version=?")
                values.append(version[:MAX_VERSION])
                fields.append("normalized_version=?")
                values.append(normalized)
            if (pending is not None or security is not None) and kind == "package" \
                    and observed_ts >= stored_observed_ts and observed_ts > 0:
                if pending is not None:
                    fields.append("pending_updates=?")
                    values.append(pending)
                if security is not None:
                    fields.append("security_updates=?")
                    values.append(security)
            if fields:
                values.append(stamp)
                values.append(row["component_id"])
                self.db.execute(
                    f"UPDATE software_components SET {', '.join(fields)},updated_at=? "
                    f"WHERE component_id=?", tuple(values))
        else:
            # Derive the initial state at creation time (instead of a hard
            # "unknown") so a first discovery lands directly in its real
            # state and the full re-derivation below writes nothing for it.
            provisional = {"component_id": None, "device_id": device_id,
                           "application_slug": application, "name": name, "kind": kind,
                           "version": version, "normalized_version": normalized,
                           "pending_updates": pending if kind == "package" else None,
                           "security_updates": security if kind == "package" else None,
                           "state": "unknown", "state_reasons_json": "[]",
                           "observed_at": observed_at or None}
            state, reasons = self._derive_state(provisional, now)
            self.db.execute(
                "INSERT INTO software_components(device_id,application_slug,name,kind,"
                "version,normalized_version,pending_updates,security_updates,source,"
                "confidence,state,state_reasons_json,observed_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?)",
                (device_id, application, name, kind, version, normalized,
                 pending if kind == "package" else None,
                 security if kind == "package" else None,
                 source[:MAX_SOURCE], 1.0, state, json.dumps(reasons),
                 observed_at, stamp, stamp))
            self._emit(device_id, "software_observed", "info",
                       f"Software component discovered: {name} "
                       f"({kind or 'unknown'}"
                       f"{f', {application}' if application else ''})",
                       {"component": name, "kind": kind, "application": application,
                        "version": version if has_version else None, "source": source})

    # -- state derivation ---------------------------------------------------------
    def _derive_state(self, row: Dict[str, Any], now: datetime) -> Tuple[str, List[str]]:
        """One component's current state from its stored facts.

        * the concrete state comes from the last observed facts (a learned
          version is current; the package component's apt counts promote it
          to update_available / security_update);
        * ``unknown`` is a component no source has ever given a real
          version (the "not installed" sentinel of the fleet's runtimes);
        * the staleness overlay then applies on top: once the last
          observation is older than the freshness floor the component
          reports *stale* while its last concrete state is preserved in
          the reasons (a failed collection never erases the last success).
        """
        ref = _component_ref(row)
        kind = row.get("kind") or ""
        normalized = row.get("normalized_version") or normalize_version(row.get("version"))
        has_version = bool(normalized) and normalized != "unknown"
        if kind == "package":
            if (row.get("security_updates") or 0) > 0:
                concrete = "security_update"
            elif (row.get("pending_updates") or 0) > 0:
                concrete = "update_available"
            else:
                concrete = "current"
        elif has_version:
            concrete = "current"
        else:
            return "unknown", [reason_code("software", "unknown", ref)
                               + (" (version never observed)" if row.get("version") is None
                                  else " (version reported as unknown -- tool not installed)")]
        age = age_seconds(row.get("observed_at"), now)
        if row.get("observed_at") is None or age is None or age > self.stale_seconds:
            code = reason_code("software", "stale", ref)
            if age is None:
                return "stale", [code + " (observation timestamp unparseable; last " + concrete + ")"]
            return "stale", [code + f" (last {concrete}; observed {int(age)}s ago, "
                                     f"floor {int(self.stale_seconds)}s)"]
        if concrete == "current":
            return "current", []
        reasons: List[str] = [reason_code("software", concrete, ref)]
        if kind == "package":
            if (row.get("security_updates") or 0) > 0:
                reasons.append(f"{row['security_updates']} security update(s) available")
            if (row.get("pending_updates") or 0) > 0:
                reasons.append(f"{row['pending_updates']} update(s) available in total")
        return concrete, reasons

    def _apply_state(self, row: Dict[str, Any], now: datetime, stamp: str) -> int:
        """Apply one re-derivation: update the state columns and record an
        event only when something actually changed (otherwise every tick
        would write -- and event -- every row)."""
        state, reasons = self._derive_state(row, now)
        stored_reasons = _loads_list(row.get("state_reasons_json"))
        if state == row.get("state") and reasons == stored_reasons:
            return 0
        self.db.execute(
            "UPDATE software_components SET state=?,state_reasons_json=?,updated_at=? "
            "WHERE component_id=?", (state, json.dumps(reasons), stamp, row["component_id"]))
        if state != row.get("state"):
            self._emit(row.get("device_id"), "software_state_changed",
                       _STATE_SEVERITY.get(state, "info"),
                       f"Software {row.get('name') or '?'} "
                       f"{row.get('state') or 'unknown'} -> {state}",
                       {"component": row.get("name"), "kind": row.get("kind"),
                        "application": row.get("application_slug"),
                        "old_state": row.get("state"), "new_state": state,
                        "reasons": reasons})
        return 1

    def _rederive_states(self, now: datetime, stamp: str) -> int:
        """Age every component under the freshness floor (spec: "track ...
        stale observations") and record an event on each real transition.
        Runs over the *entire* table -- including devices that are no
        longer in the live state -- so an offline device's last known
        posture ages to stale instead of vanishing."""
        if not self._available():
            return 0
        changes = 0
        for row in self.db.rows("SELECT * FROM software_components ORDER BY component_id"):
            try:
                changes += self._apply_state(row, now, stamp)
            except Exception:
                LOG.exception("software state re-derivation failed (%s)", row.get("component_id"))
        return changes

    # -- posture rollup -------------------------------------------------------------
    def posture(self, device: Optional[str] = None, project: Optional[str] = None) -> Dict[str, Any]:
        """A device's (or a project's) software posture rollup: worst-of
        over its components, with the contributing states counted, so the
        dashboard's needs-attention queue can rank "which machines have a
        software problem" without a live check (spec: "every monitored
        device has a software posture record")."""
        components = self._query(device=device, project=project)
        by_device: Dict[str, List[Dict[str, Any]]] = {}
        for component in components:
            by_device.setdefault(component["device_id"] or "?", []).append(component)
        devices = []
        for device_id in sorted(by_device):
            members = by_device[device_id]
            counts: Dict[str, int] = {}
            for component in members:
                counts[component["state"]] = counts.get(component["state"], 0) + 1
            state = max((c["state"] for c in members), key=lambda s: _STATE_RANK.get(s, 0))
            info = self._device_info().get(device_id)
            devices.append({
                "device_id": device_id,
                "device": info,
                "state": state,
                "component_count": len(members),
                "state_counts": counts,
            })
        worst = max((d["state"] for d in devices), key=lambda s: _STATE_RANK.get(s, 0)) if devices else "unknown"
        return {"state": worst, "device_count": len(devices), "devices": devices}
