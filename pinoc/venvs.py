"""Python virtual-environment inventory (PiNOC 2.0 Phase 1, P1-R05).

The user repeatedly maintains many venvs across Pis; this service makes that
a standard fleet capability:

* **Discovery** rides the fleet collector's due-gated ``__VENVSCAN__``
  section (``pinoc/collectors/fleet.py``). What each device scans is owned
  by :meth:`device_venv_roots` below: configured project roots, the
  repositories model's checkout trees on that device, and -- crucially --
  every venv path this service already knows (``!``-marked), so a *deleted*
  environment reports ``missing`` on the next scan instead of simply
  stopping to appear.
* **State** is freshness-driven the same way the software inventory's is:
  ``healthy`` / ``broken`` / ``inaccessible`` / ``missing`` are the concrete
  states the filesystem scan establishes; once the last scan is older than
  the staleness floor the row reports ``stale`` while its last concrete
  state is preserved in the reasons. A failed collection never erases the
  last known facts -- it only lets them age.
* **Packages** are inventoried from the site-packages dist-info listings
  (offline, nothing is ever executed) and kept as timestamped point-in-time
  snapshots in ``venv_packages`` (pruned by history maintenance on their
  own retention). The *outdated* verdicts come from the deep
  ``__VENVPKGS__`` check -- the venv's own interpreter running
  ``pip list --outdated`` read-only, which uses the network and therefore
  runs only on an explicitly requested refresh (the ``venv.refresh``
  action), never on the periodic cadence. No activation script is ever
  sourced and pip's own configuration is never read or echoed.
* **Links**: each environment associates to the repositories/applications
  models by path containment (a venv under a checkout tree belongs to that
  repository, and to the application the deployment runs), and to a project
  through the repository's or application's project, falling back to the
  device's project membership.

Phase 1 is read-only toward the environments: the only "write" the web
layer performs is :meth:`pinoc.actions.ActionDispatcher`'s ``venv.refresh``,
which requests exactly this inventory to re-scan -- it never modifies a
venv. There is deliberately no operator CRUD (spec: "No UI operation
changes a venv in Phase 1").
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from pinoc.database import Database
from pinoc.envstates import age_seconds, parse_ts, reason_code

LOG = logging.getLogger("pinoc.venvs")

#: The five states the web surfaces, in the order the spec lists them.
VENV_STATES = ("healthy", "broken", "inaccessible", "missing", "stale")
#: "unknown" rows can exist before any scan has reported them.
_STATE_RANK = {"healthy": 0, "unknown": 1, "stale": 2, "inaccessible": 3, "broken": 4, "missing": 5}
_STATE_SEVERITY = {"healthy": "info", "unknown": "info", "stale": "info",
                   "inaccessible": "warning", "broken": "warning", "missing": "warning"}
#: Scan flags the fleet reports, mapped to the concrete states above.
_FLAG_STATES = {"ok": "healthy", "broken": "broken", "inaccessible": "inaccessible", "missing": "missing"}

MAX_PATH = 400
MAX_VERSION = 64
MAX_SCAN_ROWS = 5000


class VenvError(ValueError):
    pass


class VenvNotFound(VenvError):
    pass


class VenvsService:
    """Owns the ``venvs``/``venv_packages`` tables plus the refresh loop.

    ``db`` is the shared history :class:`~pinoc.database.Database` (the
    service degrades to empty reads, never raises, when it is absent or
    unavailable -- the same contract every other PiNOC service keeps);
    ``state`` is the shared :class:`~pinoc.state.PiNOCState` (the live
    venv scan rides its ``venvs``/``venv_scan_at`` fields); ``history`` is
    the HistoryManager (discovery/state-change events go through its
    general events log); ``config`` is the top-level ``venvs``
    configuration section; ``audit``/``redact`` keep the constructor shape
    every other PiNOC service exposes (Phase 1 performs no operator writes,
    so the audit callable is only ever None or unused).
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
        self.package_retention_days = max(1, int(cfg.get("package_retention_days", 30)))
        self.roots: List[str] = [str(root) for root in (cfg.get("roots") or []) if str(root).strip()]
        self.max_venvs = max(1, int(cfg.get("max_venvs", 100)))
        self.max_packages = max(1, int(cfg.get("max_packages", 2000)))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-venvs", daemon=True)

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
                LOG.exception("venv inventory refresh failed")
            self.stop_event.wait(self.refresh_seconds)

    # -- plumbing -------------------------------------------------------------
    def _available(self) -> bool:
        return self.db is not None and bool(getattr(self.db, "available", False))

    def _devices(self) -> Dict[str, Dict[str, Any]]:
        if self.state is None:
            return {}
        return {device["id"]: device for device in self.state.devices() if device.get("id")}

    def _device_info(self) -> Dict[str, Dict[str, Any]]:
        """The known-device map: the live state first, then the devices
        table for registered devices the live state no longer carries. A
        wholesale fleet publish drops a device from the live state without
        dropping its venv rows, and a registered device with zero
        environments still deserves an honest empty posture rather than a
        404, so both sources contribute (live state wins on conflicts)."""
        info = {device_id: {"id": device_id,
                            "hostname": device.get("hostname"),
                            "friendly_name": device.get("friendly_name"),
                            "online": bool(device.get("online"))}
                for device_id, device in self._devices().items()}
        if self._available():
            for row in self.db.rows(
                    "SELECT device_id,hostname,friendly_name FROM devices"):
                device_id = row["device_id"]
                if device_id in info:
                    continue
                info[device_id] = {"id": device_id, "hostname": row.get("hostname"),
                                   "friendly_name": row.get("friendly_name"),
                                   "online": False}
        return info

    def _emit(self, device_id: Optional[str], event_type: str, severity: str,
              message: str, metadata: Dict[str, Any]) -> None:
        """Record one event through the general history events log (which
        already has its own retention), never letting event enqueueing
        break the refresh loop."""
        if self.history is None:
            return
        try:
            self.history.event(device_id, event_type, severity, message, metadata)
        except Exception:
            LOG.warning("venv event enqueue failed (%s)", event_type)

    # -- fleet spec hook ------------------------------------------------------
    def device_venv_roots(self) -> Dict[str, List[str]]:
        """Per-device scan spec for the fleet's ``__VENVSCAN__`` section.

        Three sources, in precedence order: configured project roots
        (applied to every device -- a path that does not exist on a host is
        simply skipped there), the repositories model's checkout trees on
        that device (a venv under a checkout belongs to that repository),
        and every venv path this service already knows, ``!``-marked so a
        deleted path still gets a (missing) report. Bounded: a scan spec is
        a command-line argument, so the list is capped and deduplicated.
        """
        if not self._available():
            return {}
        specs: Dict[str, List[str]] = {}
        for device_id in self._devices():
            entries: List[str] = []
            seen: Set[str] = set()

            def add(entry: str) -> None:
                entry = str(entry).strip()
                # The script splits on commas/newlines and word-splits no
                # further, but a newline in a path would still break it.
                if not entry or "\n" in entry or entry in seen:
                    return
                seen.add(entry)
                entries.append(entry[:MAX_PATH])

            for root in self.roots:
                add(root)
            for row in self.db.rows(
                    "SELECT local_path FROM deployments WHERE device_id=? "
                    "AND local_path<>'' LIMIT 50", (device_id,)):
                add(row["local_path"])
            for row in self.db.rows(
                    "SELECT path FROM venvs WHERE device_id=? ORDER BY venv_id LIMIT 100",
                    (device_id,)):
                add("!" + row["path"])
            if entries:
                specs[device_id] = entries[:40]
        return specs

    # -- row codec -----------------------------------------------------------
    def _decode_venv(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["venv_id"],
            "venv_id": row["venv_id"],
            "device_id": row["device_id"],
            "path": row["path"],
            "repo": row.get("repo_slug"),
            "app": row.get("app_slug"),
            "project": row.get("project_slug"),
            "python_version": row.get("python_version"),
            "package_count": row.get("package_count"),
            "outdated_count": row.get("outdated_count"),
            "state": row.get("state") or "unknown",
            "state_reasons": _loads_list(row.get("state_reasons_json")),
            "scanned_at": row.get("scanned_at"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _links_for(self, device_id: str, path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """(repo_slug, app_slug, project_slug) for one venv path.

        Path containment against the device's deployments (a venv inside a
        checkout tree, or directly inside the checkout) associates the
        repository and the application the deployment runs; the project
        follows from whichever of those two declares one, falling back to
        the device's own project membership. One bounded scan per device
        per tick -- all local reads.
        """
        repo = app = project = None
        for row in self.db.rows(
                "SELECT d.local_path, d.repo_slug, d.application_slug, r.project_slug AS repo_project, "
                "a.project_slug AS app_project FROM deployments d "
                "LEFT JOIN repositories r ON r.slug=d.repo_slug "
                "LEFT JOIN applications a ON a.slug=d.application_slug "
                "WHERE d.device_id=? AND d.local_path<>'' LIMIT 100", (device_id,)):
            base = row["local_path"]
            if path == base or path.startswith(base.rstrip("/") + "/"):
                if repo is None:
                    repo, app = row.get("repo_slug"), row.get("application_slug")
                    project = row.get("repo_project") or row.get("app_project")
        if project is None:
            project = self._device_project(device_id)
        return repo, app, project

    def _device_project(self, device_id: str) -> Optional[str]:
        # project_members stores the member in object_id (kind 'device' for
        # device membership) -- there is no device_id column.
        row = self.db.rows(
            "SELECT p.slug FROM project_members m JOIN projects p ON p.project_id=m.project_id "
            "WHERE m.object_id=? AND m.kind='device' AND m.removed_at IS NULL "
            "ORDER BY m.added_at DESC LIMIT 1", (device_id,))
        return row[0]["slug"] if row else None

    # -- state derivation ------------------------------------------------------
    def _derive_state(self, row: Dict[str, Any], now: datetime) -> Tuple[str, List[str]]:
        """One venv's current state from its stored facts.

        The concrete state is whatever the last scan established (its
        ``state`` column before the staleness overlay); the freshness
        overlay then applies on top: once the last observation is older
        than the floor the venv reports *stale* while its last concrete
        state is preserved in the reasons -- a failed collection never
        erases the last success, it only ages it.
        """
        ref = f"{row.get('device_id')}:{row.get('path')}"
        concrete = row.get("state") or "unknown"
        age = age_seconds(row.get("scanned_at"), now)
        if row.get("scanned_at") is None or age is None or age > self.stale_seconds:
            code = reason_code("venv", "stale", ref)
            if age is None:
                return "stale", [code + " (scan timestamp unparseable; last " + concrete + ")"]
            return "stale", [code + f" (last {concrete}; scanned {int(age)}s ago, "
                                     f"floor {int(self.stale_seconds)}s)"]
        return concrete, self._concrete_reasons(concrete, ref)

    def _concrete_reasons(self, concrete: str, ref: str) -> List[str]:
        """The human-readable reasons one *fresh* concrete state carries.

        Shared by the scan application (which writes the concrete state and
        these exact reasons on each new scan, so the full re-derivation in
        the same tick finds nothing to change) and by the re-derivation
        itself.
        """
        if concrete == "healthy":
            return []
        reasons = [reason_code("venv", concrete, ref)]
        if concrete == "broken":
            reasons.append("interpreter or base environment missing")
        if concrete == "inaccessible":
            reasons.append("directory not readable or executable")
        if concrete == "missing":
            reasons.append("path no longer exists")
        return reasons

    # -- refresh ---------------------------------------------------------------
    def tick(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """One source-refresh + full state re-derivation. Called by the
        background thread on ``refresh_seconds`` cadence and by tests
        directly; it is all local reads plus this service's own tables."""
        if not self._available():
            return {"status": "unavailable"}
        now = now or datetime.now(timezone.utc)
        stamp = now.isoformat()
        devices = self._devices()
        applied = 0
        for device_id, device in sorted(devices.items()):
            scan_at = device.get("venv_scan_at")
            for entry in device.get("venvs") or []:
                path = str(entry.get("path") or "").strip()
                if not path:
                    continue
                try:
                    self._apply_venv(device_id, entry, scan_at or stamp, stamp)
                    applied += 1
                except Exception:
                    LOG.exception("venv observation failed (%s)", path)
        state_changes = self._rederive_states(now, stamp)
        return {"status": "ok", "observations": applied,
                "state_changes": state_changes}

    def _apply_venv(self, device_id: str, entry: Dict[str, Any],
                    scanned_at: str, stamp: str) -> None:
        """Upsert one venv from one scan entry and refresh its package
        snapshot. Timestamps only move forward; learned facts are replaced
        only by *newer* scans, so a failed poll can never rewind or erase
        them."""
        path = str(entry.get("path") or "")[:MAX_PATH]
        scan_ts = _ts_value(scanned_at)
        packages = [package for package in entry.get("packages") or []
                    if isinstance(package, dict) and package.get("name")][:self.max_packages]
        flags = str(entry.get("flags") or "")
        concrete = _FLAG_STATES.get(flags, "unknown")
        ref = f"{device_id}:{path}"
        try:
            count = int(entry.get("package_count"))
        except (TypeError, ValueError):
            count = None
        if count is None:
            count = len(packages) or None
        version = str(entry.get("python") or "")[:MAX_VERSION] or None
        existing = self.db.rows(
            "SELECT * FROM venvs WHERE device_id=? AND path=?", (device_id, path))
        if existing:
            row = existing[0]
            stored_ts = _ts_value(row.get("scanned_at"))
            fields: List[str] = []
            values: List[Any] = []
            # A late (older than what is stored) scan rewrites nothing: the
            # row already holds newer facts, and the package snapshot keeps
            # its own, newer, timestamp.
            if scan_ts >= stored_ts and scan_ts > 0:
                if version is not None:
                    fields.append("python_version=?"); values.append(version)
                if count is not None:
                    fields.append("package_count=?"); values.append(count)
                fields.append("source=?"); values.append("fleet_venvscan")
                fields.append("state=?"); values.append(concrete)
                fields.append("state_reasons_json=?")
                values.append(json.dumps(self._concrete_reasons(concrete, ref)))
                fields.append("scanned_at=?"); values.append(scanned_at)
                fields.append("updated_at=?"); values.append(stamp)
            venv_id = row["venv_id"]
            if fields:
                values.append(venv_id)
                self.db.execute(
                    f"UPDATE venvs SET {', '.join(fields)} WHERE venv_id=?", tuple(values))
                outdated_count = self._apply_packages(venv_id, device_id, packages, flags, stamp)
                if outdated_count is not None:
                    self.db.execute("UPDATE venvs SET outdated_count=? WHERE venv_id=?",
                                    (outdated_count, venv_id))
        else:
            self.db.execute(
                "INSERT INTO venvs(device_id,path,repo_slug,app_slug,project_slug,"
                "python_version,package_count,outdated_count,state,state_reasons_json,"
                "source,confidence,scanned_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (device_id, path) + self._links_for(device_id, path) +
                (version, count, None, concrete, json.dumps(self._concrete_reasons(concrete, ref)),
                 "fleet_venvscan", 1.0, scanned_at, stamp, stamp))
            self._emit(device_id, "venv_discovered", "info",
                       f"Python venv discovered: {path} (python {version or 'unknown'})",
                       {"path": path, "python": version, "flags": flags})
            venv_id = self.db.scalar("SELECT venv_id FROM venvs WHERE device_id=? AND path=?",
                                     (device_id, path))
            outdated_count = self._apply_packages(venv_id, device_id, packages, flags, stamp)
            if outdated_count is not None:
                self.db.execute("UPDATE venvs SET outdated_count=? WHERE venv_id=?",
                                (outdated_count, venv_id))
        # Learned associations only gain, never fight the scan: the scan
        # itself carries no repo/app knowledge.
        self.db.execute(
            "UPDATE venvs SET repo_slug=COALESCE(?,repo_slug),app_slug=COALESCE(?,app_slug),"
            "project_slug=COALESCE(?,project_slug),updated_at=? WHERE venv_id=(SELECT venv_id FROM venvs WHERE device_id=? AND path=?)",
            self._links_for(device_id, path) + (stamp, device_id, path))

    def _apply_packages(self, venv_id: Optional[int], device_id: str,
                        packages: List[Dict[str, Any]], flags: str,
                        stamp: str) -> Optional[int]:
        """Write this scan's package snapshot (point-in-time, like the
        application health snapshots). The outdated flags come from the
        deep pip check when it ran; when it did not (the periodic
        filesystem-only scan -- or a venv whose interpreter is gone), the
        previous snapshot's *definite* flags are carried over by name: the
        last known verdict, so a routine scan does not blind the inventory
        and does not turn a never-checked package into a fake "current".
        A *missing* or *inaccessible* environment freezes its last
        snapshot (its packages are gone or unreadable; what the listing
        last showed stays visible, aging out on the retention alone).
        Returns the snapshot's outdated count (0 included) when any
        definite flag exists in it, else None ("keep what was stored")."""
        if venv_id is None or flags in ("missing", "inaccessible"):
            return None
        had_verdicts = any(package.get("outdated") is not None for package in packages)
        previous: Dict[str, Dict[str, Any]] = {}
        if not had_verdicts and packages:
            rows = self.db.rows(
                "SELECT name,outdated,latest_version FROM venv_packages WHERE venv_id=? "
                "ORDER BY scanned_at DESC LIMIT 5000", (venv_id,))
            for row in rows:
                previous.setdefault(row["name"], row)
        rows = []
        for package in packages:
            name = str(package.get("name") or "")[:200]
            if not name:
                continue
            outdated = package.get("outdated")
            latest = package.get("latest_version")
            if outdated is None and name in previous:
                stored_flag = previous[name].get("outdated")
                if stored_flag is not None:
                    outdated = bool(stored_flag)
                    latest = previous[name].get("latest_version")
            rows.append((venv_id, device_id, name,
                         str(package.get("version") or "")[:MAX_VERSION] or None,
                         1 if outdated else (0 if outdated is False else None),
                         latest[:MAX_VERSION] if latest else None, stamp))
        self.db.execute("DELETE FROM venv_packages WHERE venv_id=?", (venv_id,))
        if rows:
            self.db.executemany(
                "INSERT INTO venv_packages(venv_id,device_id,name,version,outdated,latest_version,scanned_at) "
                "VALUES(?,?,?,?,?,?,?)", rows)
        if not rows:
            return 0
        definite = [row for row in rows if row[4] is not None]
        if not definite:
            return None
        return sum(1 for row in definite if row[4] == 1)

    def _rederive_states(self, now: datetime, stamp: str) -> int:
        """Age every venv under the freshness floor and record an event on
        each real transition. Runs over the *entire* table -- including
        devices no longer in the live state -- so an offline device's last
        known environments age to stale instead of vanishing."""
        if not self._available():
            return 0
        changes = 0
        for row in self.db.rows("SELECT * FROM venvs ORDER BY venv_id"):
            try:
                changes += self._apply_state(row, now, stamp)
            except Exception:
                LOG.exception("venv state re-derivation failed (%s)", row.get("venv_id"))
        return changes

    def _apply_state(self, row: Dict[str, Any], now: datetime, stamp: str) -> int:
        state, reasons = self._derive_state(row, now)
        stored_reasons = _loads_list(row.get("state_reasons_json"))
        if state == row.get("state") and reasons == stored_reasons:
            return 0
        self.db.execute(
            "UPDATE venvs SET state=?,state_reasons_json=?,updated_at=? WHERE venv_id=?",
            (state, json.dumps(reasons), stamp, row["venv_id"]))
        if state != row.get("state"):
            self._emit(row.get("device_id"), "venv_state_changed",
                       _STATE_SEVERITY.get(state, "info"),
                       f"Python venv {row.get('path')} {row.get('state') or 'unknown'} -> {state}",
                       {"path": row.get("path"), "old_state": row.get("state"),
                        "new_state": state, "reasons": reasons})
        return 1

    # -- read API ----------------------------------------------------------------
    def _filter_clause(self, device: Optional[str], state: Optional[str],
                       project: Optional[str], repo: Optional[str],
                       app: Optional[str]) -> Tuple[str, List[Any]]:
        where, args = ["1=1"], []
        if device:
            where.append("device_id=?")
            args.append(str(device).strip())
        if state:
            if state not in VENV_STATES + ("unknown",):
                raise VenvError(f"state must be one of {', '.join(VENV_STATES + ('unknown',))}")
            where.append("state=?")
            args.append(state)
        if project:
            where.append("project_slug=?")
            args.append(str(project).strip())
        if repo:
            where.append("repo_slug=?")
            args.append(str(repo).strip())
        if app:
            where.append("app_slug=?")
            args.append(str(app).strip())
        return " AND ".join(where), args

    def _query(self, device: Optional[str] = None, state: Optional[str] = None,
               project: Optional[str] = None, repo: Optional[str] = None,
               app: Optional[str] = None, limit: int = 5000) -> List[Dict[str, Any]]:
        if not self._available():
            return []
        where, args = self._filter_clause(device, state, project, repo, app)
        rows = self.db.rows(
            "SELECT * FROM venvs WHERE " + where +
            " ORDER BY device_id,path LIMIT ?", args + [int(limit)])
        venvs = [self._decode_venv(row) for row in rows]
        devices = self._device_info()
        for venv in venvs:
            venv["device"] = devices.get(venv["device_id"])
        return venvs

    def list(self, device: Optional[str] = None, state: Optional[str] = None,
             project: Optional[str] = None, repo: Optional[str] = None,
             app: Optional[str] = None) -> List[Dict[str, Any]]:
        """The venv inventory, filtered like every other fleet view and
        sorted worst-state-first within each device so the queue an
        operator cares about ranks to the top."""
        venvs = self._query(device=device, state=state, project=project,
                            repo=repo, app=app)
        venvs.sort(key=lambda v: (v["device_id"] or "",
                                  -_STATE_RANK.get(v["state"], 0),
                                  v["path"] or ""))
        return venvs

    def attention(self, limit: int = 200) -> List[Dict[str, Any]]:
        """The fleet view's "environments needing attention": every venv
        whose state is not healthy, worst first."""
        venvs = [v for v in self._query(limit=MAX_SCAN_ROWS)
                 if v["state"] != "healthy"]
        venvs.sort(key=lambda v: (-_STATE_RANK.get(v["state"], 0),
                                  v["device_id"] or "", v["path"] or ""))
        return venvs[:max(1, int(limit))]

    def device_venvs(self, device_id: Any) -> Optional[Dict[str, Any]]:
        """One device's venv posture (GET /devices/{id}/venvs): all its
        environments plus its worst rollup state."""
        if not self._available():
            return None
        key = str(device_id).strip()
        rows = self.db.rows("SELECT * FROM venvs WHERE device_id=? ORDER BY path", (key,))
        if not rows and not self._device_info().get(key):
            return None
        venvs = [self._decode_venv(row) for row in rows]
        devices = self._device_info()
        for venv in venvs:
            venv["device"] = devices.get(key)
        counts: Dict[str, int] = {}
        for venv in venvs:
            counts[venv["state"]] = counts.get(venv["state"], 0) + 1
        rollup = (max((v["state"] for v in venvs), key=lambda s: _STATE_RANK.get(s, 0))
                  if venvs else "unknown")
        summary = ", ".join(f"{counts[s]} {s}" for s in ("missing", "broken", "inaccessible",
                                                         "stale", "unknown", "healthy")
                            if counts.get(s))
        return {
            "device": devices.get(key) or {"id": key},
            "state": rollup,
            "venv_count": len(venvs),
            "state_counts": counts,
            "state_reasons": [f"{len(venvs)} environment(s): {summary}"] if venvs else [],
            "venvs": venvs,
        }

    def venv(self, venv_id: Any) -> Optional[Dict[str, Any]]:
        if not self._available():
            return None
        try:
            key = int(venv_id)
        except (TypeError, ValueError):
            return None
        row = self.db.rows("SELECT * FROM venvs WHERE venv_id=?", (key,))
        if not row:
            return None
        decoded = self._decode_venv(row[0])
        decoded["device"] = self._device_info().get(decoded["device_id"])
        return decoded

    def packages(self, venv_id: Any, limit: int = 1000) -> Optional[Dict[str, Any]]:
        """One venv's last package snapshot with a timestamp and the
        outdated summary. A venv that was never deep-refreshed has a
        filesystem inventory with no outdated verdicts -- the summary says
        so rather than guessing."""
        if not self._available():
            return None
        venv = self.venv(venv_id)
        if venv is None:
            return None
        # The snapshot is one timestamped point in time: select the newest
        # snapshot's rows only (an older snapshot never leaks through the
        # limit), sorted by name so the listing reads stably.
        snapshot_at = self.db.scalar(
            "SELECT MAX(scanned_at) FROM venv_packages WHERE venv_id=?", (venv["venv_id"],))
        if snapshot_at is None:
            return {"venv": venv, "snapshot_at": None, "package_count": 0,
                    "outdated_count": None, "packages": []}
        rows = self.db.rows(
            "SELECT name,version,outdated,latest_version FROM venv_packages "
            "WHERE venv_id=? AND scanned_at=? ORDER BY name LIMIT ?",
            (venv["venv_id"], snapshot_at, max(1, int(limit))))
        packages = [{
            "name": row["name"],
            "version": row.get("version"),
            "outdated": None if row.get("outdated") is None else bool(row["outdated"]),
            "latest_version": row.get("latest_version"),
        } for row in rows]
        definite = [package for package in packages if package["outdated"] is not None]
        return {
            "venv": venv,
            "snapshot_at": snapshot_at,
            "package_count": len(packages),
            "outdated_count": sum(1 for package in definite if package["outdated"]) if definite else None,
            "packages": packages,
        }


# -- module helpers ----------------------------------------------------------

def _loads_list(raw: Any) -> List[Any]:
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def _ts_value(value: Any) -> float:
    """A stored ISO timestamp as epoch seconds (0 for absent/unparseable)."""
    parsed = parse_ts(value)
    return parsed.timestamp() if parsed is not None else 0.0
