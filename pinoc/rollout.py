"""Staged fleet software maintenance ("rolling updates").

A *rollout run* applies apt updates (``pinoc.actions.ActionDispatcher``'s
``apt.upgrade`` action) across a selected set of devices in waves: an
explicit canary group (or the first ``canary_count`` selected devices) goes
first, then the remainder follows in one or more subsequent waves (chunked
by ``wave_size`` when given). After every device in a wave finishes
updating -- and rebooting, if the update left a reboot pending -- a health
gate must pass for the *whole* wave before the next one is allowed to
start. A gate failure halts the rollout outright: later waves never run,
and a notification goes out over the existing notification path, the same
way :class:`pinoc.schedules.ScheduleService` reports a repeatedly failing
schedule.

Like :class:`pinoc.schedules.ScheduleService` and
:class:`pinoc.remediation.RemediationService`, this is a poll-loop
("tick") service layered on top of the shared
:class:`pinoc.actions.ActionDispatcher` -- every apt update and every
reboot it issues is a normal queued action job, indistinguishable in the
job and audit tables from a manual or scheduled one (``requested_by``
carries ``'rollout'`` and a ``run_id``/``wave`` parameter).

Per-device state lives in ``rollout_devices``, one row per
``(run_id, device_id)``, carrying the wave it belongs to, its status, the
kernel version and pending-update count observed just before and just
after its update, and the job ids of the update/reboot actions that ran
for it. ``rollout_runs`` carries the run's own configuration and overall
status; :meth:`RolloutService.summary` aggregates ``rollout_devices`` by
status into the "how did this run go" rollup a results view would show
without maintaining a second, independently-updatable summary row that
could drift out of sync with the per-device rows it summarizes.

Maintenance windows
--------------------
A device only has its update dispatched while it reports as being inside
its own configured maintenance window (``device.get("maintenance")`` --
the same per-device maintenance-window state
:meth:`pinoc.actions.ActionDispatcher.set_maintenance` and the
``maintenance: true`` device-config flag already drive; see
:mod:`pinoc.health`'s own use of the same flag). This is checked
per-device, every tick, not just once at wave start, so a wave's devices
that enter maintenance at different times each start as soon as their own
window opens rather than waiting for every device in the wave to be ready
at once. A run created with ``respect_maintenance=False`` skips this gate
entirely (useful for an operator-declared maintenance period tracked
outside PiNOC).

Health gate
-----------
A device's health gate is :func:`pinoc.health.evaluate`'s live
classification, already read from the shared state cache the same as
everywhere else in PiNOC: the device must not be reporting ``critical``
health, and -- if its update left a reboot pending -- must have come back
online within :data:`REBOOT_TIMEOUT_SECONDS`. This reads the state cache's
existing health classification rather than forcing a fresh collection
cycle, so the verdict can lag by up to one normal poll interval; that is
the same staleness every other PiNOC feature built on ``state.device()``
already accepts.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pinoc.actions import ActionError
from pinoc.database import utcnow

LOG = logging.getLogger("pinoc.rollout")
UTC = timezone.utc

SCOPES = ("security", "all")
# Device-row states that still need work from a future tick.
_ACTIVE_STATUSES = ("not_started", "pending", "updating", "rebooting", "verifying")
# Device-row states a wave (and therefore the run) is done with.
_TERMINAL_STATUSES = ("succeeded", "failed", "skipped")
# How long to wait for a device to come back online after a reboot the
# update triggered before treating the health gate as failed.
REBOOT_TIMEOUT_SECONDS = 900


def now_utc() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: Any) -> datetime:
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _packages_updates_available(device: Dict[str, Any]) -> Optional[int]:
    packages = (device.get("applications") or {}).get("packages")
    if not isinstance(packages, dict):
        return None
    value = packages.get("updates_available")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def plan_waves(device_ids: List[str], canary_device_ids: Optional[List[str]] = None,
               canary_count: int = 0, wave_size: Optional[int] = None) -> List[List[str]]:
    """Split a selected device set into an ordered wave plan.

    Wave 0 is the canary group: an explicit ``canary_device_ids`` list
    (filtered to devices actually in the selection) if given, otherwise the
    first ``canary_count`` selected devices in a deterministic (sorted)
    order. Every remaining device follows in one wave, or -- when
    ``wave_size`` is given -- in successive fixed-size waves.
    """
    ordered = sorted(dict.fromkeys(device_ids))
    selected = set(ordered)
    canary = [d for d in dict.fromkeys(canary_device_ids or []) if d in selected]
    if not canary and canary_count > 0:
        canary = ordered[:canary_count]
    remaining = [d for d in ordered if d not in set(canary)]
    waves: List[List[str]] = [canary] if canary else []
    if remaining:
        if wave_size and wave_size > 0:
            waves.extend(remaining[i:i + wave_size] for i in range(0, len(remaining), wave_size))
        else:
            waves.append(remaining)
    return waves


class RolloutService:
    """Owns ``rollout_runs``/``rollout_devices`` and drives staged fleet updates.

    ``actions`` is the shared :class:`pinoc.actions.ActionDispatcher`; every
    update and reboot this service issues goes through it, so a rollout run
    shows up in ``action_jobs`` and the audit trail exactly like a manual or
    scheduled action.
    """

    def __init__(self, db, actions, state=None, notifier=None, interval: int = 20) -> None:
        self.db = db
        self.actions = actions
        self.state = state
        self.notifier = notifier
        self.interval = max(5, int(interval))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-rollout", daemon=True)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self.db is not None and self.actions is not None:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    # -- reads -----------------------------------------------------------------
    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM rollout_runs WHERE run_id=?", (run_id,))
        return rows[0] if rows else None

    def list(self) -> List[Dict[str, Any]]:
        return self.db.rows("SELECT * FROM rollout_runs ORDER BY created_at DESC")

    def devices(self, run_id: str) -> List[Dict[str, Any]]:
        return self.db.rows(
            "SELECT * FROM rollout_devices WHERE run_id=? ORDER BY wave ASC, device_id ASC", (run_id,))

    def summary(self, run_id: str) -> Dict[str, Any]:
        rows = self.devices(run_id)
        counts: Dict[str, int] = {}
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        return {"total": len(rows), "by_status": counts}

    # -- creation ------------------------------------------------------------
    def create_run(self, *, name: str = "", scope: str, roles: Optional[List[str]] = None,
                   tags: Optional[List[str]] = None, device_ids: Optional[List[str]] = None,
                   canary_device_ids: Optional[List[str]] = None, canary_count: int = 0,
                   wave_size: Optional[int] = None, respect_maintenance: bool = True,
                   requested_by: str, role: str = "administrator",
                   source_ip: Optional[str] = None) -> Dict[str, Any]:
        scope = str(scope or "").strip().lower()
        if scope not in SCOPES:
            raise ValueError("scope must be 'security' or 'all'")
        if self.state is None:
            raise ValueError("fleet state is unavailable")
        selected = self._resolve_devices(roles, tags, device_ids)
        if not selected:
            raise ValueError("no devices matched the selection")
        not_approved = [d["id"] for d in selected if "apt.upgrade" not in (d.get("allowed_actions") or [])]
        if not_approved:
            raise ValueError(f"apt.upgrade is not approved on: {', '.join(sorted(not_approved))}")
        waves = plan_waves([d["id"] for d in selected], canary_device_ids, int(canary_count or 0),
                           int(wave_size) if wave_size else None)
        if not waves:
            raise ValueError("wave plan is empty")
        run_id = str(uuid.uuid4())
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO rollout_runs(run_id,name,scope,device_selector_json,canary_count,wave_size,"
            "respect_maintenance,status,current_wave,wave_count,requested_by,created_at,updated_at,started_at) "
            "VALUES(?,?,?,?,?,?,?,?,0,?,?,?,?,?)",
            (run_id, str(name or ""), scope,
             json.dumps({"roles": roles or [], "tags": tags or [], "device_ids": device_ids or []}),
             int(canary_count or 0), int(wave_size) if wave_size else None, 1 if respect_maintenance else 0,
             "running", len(waves), requested_by, stamp, stamp, stamp))
        for wave_index, wave in enumerate(waves):
            status = "pending" if wave_index == 0 else "not_started"
            for device_id in wave:
                self.db.execute(
                    "INSERT INTO rollout_devices(run_id,device_id,wave,status,updated_at) VALUES(?,?,?,?,?)",
                    (run_id, device_id, wave_index, status, stamp))
        self.actions.audit(requested_by, role, source_ip, None, "rollout.create", None,
                           {"run_id": run_id, "scope": scope, "waves": [len(w) for w in waves]},
                           "allowed", "running")
        return self.get(run_id)

    def cancel(self, run_id: str, *, requested_by: str, role: str = "administrator",
              source_ip: Optional[str] = None) -> Dict[str, Any]:
        run = self.get(run_id)
        if run is None:
            raise ValueError("rollout not found")
        if run["status"] != "running":
            return run
        self._halt(run, f"cancelled by {requested_by}", actor=requested_by, role=role, source_ip=source_ip)
        return self.get(run_id)

    def _resolve_devices(self, roles: Optional[List[str]], tags: Optional[List[str]],
                         device_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
        roles_set = {str(r).lower() for r in (roles or [])}
        tags_set = {str(t).lower() for t in (tags or [])}
        ids_set = {str(d) for d in (device_ids or [])}
        matched = []
        for device in self.state.devices():
            if ids_set and device.get("id") not in ids_set:
                continue
            if roles_set and not (roles_set & {str(r).lower() for r in device.get("roles") or []}):
                continue
            if tags_set and not (tags_set & {str(t).lower() for t in device.get("tags") or []}):
                continue
            if not ids_set and not roles_set and not tags_set:
                continue  # require an explicit selection; never silently target the whole fleet
            matched.append(device)
        return matched

    # -- engine ------------------------------------------------------------
    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                LOG.exception("rollout tick failed")
            self.stop_event.wait(self.interval)

    def tick(self) -> None:
        if self.db is None or self.actions is None or not self.db.available:
            return
        for run in self.db.rows("SELECT * FROM rollout_runs WHERE status='running'"):
            try:
                self._advance(run)
            except Exception:
                LOG.exception("rollout advance failed for run %s", run.get("run_id"))

    def _advance(self, run: Dict[str, Any]) -> None:
        rows = self.db.rows(
            "SELECT * FROM rollout_devices WHERE run_id=? AND wave=? ORDER BY device_id",
            (run["run_id"], run["current_wave"]))
        for row in rows:
            current = self.get(run["run_id"])
            if current is None or current["status"] != "running":
                return  # halted (or completed) by an earlier row this same tick
            if row["status"] == "pending":
                self._maybe_dispatch_update(current, row)
            elif row["status"] == "updating":
                self._reconcile_update(current, row)
            elif row["status"] == "rebooting":
                self._reconcile_reboot(current, row)
            elif row["status"] == "verifying":
                self._verify_health(current, row)
        current = self.get(run["run_id"])
        if current is not None and current["status"] == "running":
            self._maybe_advance_wave(current)

    def _maybe_dispatch_update(self, run: Dict[str, Any], row: Dict[str, Any]) -> None:
        device_id = row["device_id"]
        device = self.state.device(device_id) if self.state is not None else None
        if device is None:
            self._fail_device(run, row, "device not found")
            return
        if run["respect_maintenance"] and not device.get("maintenance"):
            return  # still waiting for this device's own maintenance window
        before_kernel = device.get("kernel") or ""
        before_updates = _packages_updates_available(device)
        try:
            job = self.actions.enqueue("apt.upgrade", device_id, run["scope"], "rollout", "administrator",
                                       None, {"run_id": run["run_id"], "wave": row["wave"]})
        except ActionError as exc:
            self._fail_device(run, row, str(exc))
            return
        stamp = utcnow()
        self.db.execute(
            "UPDATE rollout_devices SET status='updating',update_job_id=?,before_kernel=?,"
            "before_updates_available=?,dispatched_at=?,updated_at=? WHERE id=?",
            (job["job_id"], before_kernel, before_updates, stamp, stamp, row["id"]))

    def _job(self, job_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not job_id:
            return None
        return self.actions.get(job_id)

    def _reconcile_update(self, run: Dict[str, Any], row: Dict[str, Any]) -> None:
        job = self._job(row["update_job_id"])
        if job is None or job["status"] in ("queued", "running"):
            return
        if job["status"] != "succeeded":
            self._fail_device(run, row, job.get("error") or f"apt.upgrade {job['status']}")
            return
        reboot_required = "reboot_required=1" in (job.get("summary") or "")
        stamp = utcnow()
        if reboot_required:
            try:
                reboot_job = self.actions.enqueue("device.reboot", row["device_id"], None, "rollout",
                                                  "administrator", None,
                                                  {"run_id": run["run_id"], "wave": row["wave"]})
            except ActionError as exc:
                self._fail_device(run, row, str(exc))
                return
            self.db.execute(
                "UPDATE rollout_devices SET status='rebooting',reboot_job_id=?,reboot_required=1,"
                "reboot_at=?,updated_at=? WHERE id=?",
                (reboot_job["job_id"], stamp, stamp, row["id"]))
        else:
            self.db.execute(
                "UPDATE rollout_devices SET status='verifying',updated_at=? WHERE id=?", (stamp, row["id"]))

    def _reconcile_reboot(self, run: Dict[str, Any], row: Dict[str, Any]) -> None:
        job = self._job(row["reboot_job_id"])
        if job is None or job["status"] in ("queued", "running"):
            return
        if job["status"] != "succeeded":
            self._fail_device(run, row, job.get("error") or f"device.reboot {job['status']}")
            return
        self.db.execute(
            "UPDATE rollout_devices SET status='verifying',updated_at=? WHERE id=?", (utcnow(), row["id"]))

    def _verify_health(self, run: Dict[str, Any], row: Dict[str, Any]) -> None:
        device = self.state.device(row["device_id"]) if self.state is not None else None
        reference = row["reboot_at"] or row["dispatched_at"] or row["updated_at"]
        waited = (now_utc() - _as_utc(reference)).total_seconds()
        if row["reboot_required"] and (device is None or not device.get("online")):
            if waited > REBOOT_TIMEOUT_SECONDS:
                self._fail_device(run, row, "device did not come back online after its update reboot")
            return  # keep waiting for the device to return
        if device is None:
            if waited > REBOOT_TIMEOUT_SECONDS:
                self._fail_device(run, row, "device not found during health verification")
            return
        if device.get("health") == "critical":
            self._fail_device(run, row, "critical health after update: " +
                              "; ".join(device.get("health_reasons") or []))
            return
        after_kernel = device.get("kernel") or ""
        after_updates = _packages_updates_available(device)
        stamp = utcnow()
        self.db.execute(
            "UPDATE rollout_devices SET status='succeeded',after_kernel=?,after_updates_available=?,"
            "completed_at=?,updated_at=? WHERE id=?",
            (after_kernel, after_updates, stamp, stamp, row["id"]))
        self.actions.audit("rollout", "administrator", None, row["device_id"], "rollout.device_succeeded",
                           None, {"run_id": run["run_id"], "wave": row["wave"]}, "allowed", "succeeded")

    def _fail_device(self, run: Dict[str, Any], row: Dict[str, Any], error: str) -> None:
        stamp = utcnow()
        self.db.execute(
            "UPDATE rollout_devices SET status='failed',error=?,completed_at=?,updated_at=? WHERE id=?",
            (str(error)[:500], stamp, stamp, row["id"]))
        self.actions.audit("rollout", "administrator", None, row["device_id"], "rollout.device_failed", None,
                           {"run_id": run["run_id"], "wave": row["wave"], "error": str(error)[:500]},
                           "allowed", "failed", error=str(error)[:500])
        self._halt(run, f"{row['device_id']}: {error}")

    def _maybe_advance_wave(self, run: Dict[str, Any]) -> None:
        rows = self.db.rows(
            "SELECT status FROM rollout_devices WHERE run_id=? AND wave=?", (run["run_id"], run["current_wave"]))
        if not rows or any(r["status"] in _ACTIVE_STATUSES for r in rows):
            return
        if any(r["status"] == "failed" for r in rows):
            self._halt(run, "a device failed its update or health gate")
            return
        stamp = utcnow()
        next_wave = run["current_wave"] + 1
        if next_wave >= run["wave_count"]:
            self.db.execute(
                "UPDATE rollout_runs SET status='completed',completed_at=?,updated_at=? WHERE run_id=?",
                (stamp, stamp, run["run_id"]))
            self.actions.audit("rollout", "administrator", None, None, "rollout.completed", None,
                               {"run_id": run["run_id"]}, "allowed", "completed")
            return
        self.db.execute(
            "UPDATE rollout_runs SET current_wave=?,updated_at=? WHERE run_id=?",
            (next_wave, stamp, run["run_id"]))
        self.db.execute(
            "UPDATE rollout_devices SET status='pending',updated_at=? WHERE run_id=? AND wave=?",
            (stamp, run["run_id"], next_wave))

    def _halt(self, run: Dict[str, Any], reason: str, actor: str = "rollout", role: str = "administrator",
             source_ip: Optional[str] = None) -> None:
        current = self.get(run["run_id"])
        if current is None or current["status"] != "running":
            return  # already halted/completed by a concurrent path
        stamp = utcnow()
        self.db.execute(
            "UPDATE rollout_runs SET status='halted',halted_reason=?,completed_at=?,updated_at=? "
            "WHERE run_id=?", (str(reason)[:500], stamp, stamp, run["run_id"]))
        self.db.execute(
            "UPDATE rollout_devices SET status='skipped',updated_at=? WHERE run_id=? AND status IN "
            "('not_started','pending')", (stamp, run["run_id"]))
        self.actions.audit(actor, role, source_ip, None, "rollout.halted", None,
                           {"run_id": run["run_id"], "reason": str(reason)[:500]}, "allowed", "halted")
        if self.notifier is not None and getattr(self.notifier, "enabled", False):
            try:
                self.notifier.enqueue("open", {
                    "severity": "critical", "alert_type": "rollout_halted",
                    "message": f"Fleet update rollout {run['run_id']} halted: {reason}"[:500],
                    "device_id": None,
                })
            except Exception:  # noqa: BLE001 - a notification failure must not break the tick
                LOG.exception("rollout halt notification failed")
