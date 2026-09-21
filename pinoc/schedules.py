"""Persistent, cron-style scheduler for allowlisted operational actions.

A *schedule* binds one registry action (see :mod:`pinoc.actions`) to one
device, an optional target, and a firing spec.  Firing is driven by a single
daemon thread that wakes every ``interval`` seconds, reconciles the outcome of
previously queued jobs, and enqueues any schedule whose ``next_run`` has passed.

Firing spec
-----------
Three forms are accepted (stored verbatim in ``action_schedules.spec``):

* standard five-field cron  -- ``minute hour day-of-month month day-of-week``
  supporting ``*``, ``*/n``, ``a-b``, ``a-b/n`` and comma lists, e.g.
  ``0 3 * * *`` (03:00 daily);
* a cron alias              -- ``@hourly``, ``@daily``/``@midnight``,
  ``@weekly``, ``@monthly``, ``@yearly``;
* a one-shot                -- ``once:<ISO-8601 timestamp>``.  A one-shot
  fires a single time and is then consumed (its ``next_run`` becomes ``NULL``).

Each schedule carries a timezone (IANA name, default ``UTC``); the spec is
evaluated in that zone and the stored ``next_run`` is normalised to UTC.

Failure handling
----------------
Dispatch and job outcomes update ``consecutive_failures``:

* a *dispatch failure* (the action could not even be queued -- the device is
  offline, the target is no longer approved, ...) increments the counter and
  retries on a short cadence;
* a *job* that reaches a non-success terminal state increments the counter but
  waits for the next scheduled slot (a destructive action is never retried in a
  tight loop);
* a successful job resets the counter to zero;
* once the counter reaches :data:`MAX_CONSECUTIVE_FAILURES` the schedule is
  auto-paused, a critical event is recorded, and a notification is enqueued.
  It stays paused until an operator resumes it.

Everything is audited through the action dispatcher's audit trail, so a
schedule's lifecycle is visible in the same records as manual actions.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from pinoc.actions import (
    RESCUE_ACTIONS,
    ActionError,
    UNIT,
    VACUUM_SPEC_RE,
    valid_log_path,
)
from pinoc.database import utcnow
from pinoc.security import redact

LOG = logging.getLogger("pinoc.schedules")

UTC = timezone.utc

# Auto-pause a schedule after this many consecutive dispatch/job failures.
MAX_CONSECUTIVE_FAILURES = 3
# Retry cadence (minutes) after a *dispatch* failure (the action never ran).
RETRY_MINUTES = 5
# How far ahead to scan for the next firing time before declaring a spec
# unsatisfiable.  Two years is ample for real maintenance windows; the
# field-aware scan below makes even unsatisfiable specs cheap.
HORIZON_DAYS = 366 * 2

# Common shorthand so operators do not have to spell out cron fields.
ALIASES = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
}

# (lo, hi) for the five cron fields, in order.  Day-of-week accepts 0-7
# (both 0 and 7 mean Sunday); 7 is normalised to 0 after parsing.
_FIELD_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
_TERMINAL = ("succeeded", "failed", "timed_out", "cancelled")


def now_utc() -> datetime:
    return datetime.now(UTC)


def _tz(name: Optional[str]):
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(name or "UTC")
    except Exception:
        return UTC


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _parse_once(value: str, tz_name: str = "UTC") -> datetime:
    """Parse a ``once:`` timestamp; a naive value is assumed to be in ``tz_name``."""
    value = str(value).strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_tz(tz_name))
    return dt.astimezone(UTC)


def _parse_field(field: str, lo: int, hi: int):
    """Expand one cron field into ``(set of values, restricted)``.

    ``restricted`` is True when the raw field is not a bare ``*``; it feeds the
    standard day-of-month / day-of-week OR rule in :func:`next_after`.
    """
    field = str(field).strip()
    restricted = field != "*"
    values = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty element in cron field")
        step = 1
        base = part
        if "/" in part:
            base, _, step_text = part.partition("/")
            if not step_text.strip().isdigit() or int(step_text) < 1:
                raise ValueError("invalid step in cron field")
            step = int(step_text)
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, _, b = base.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise ValueError("invalid range in cron field")
            start, end = int(a), int(b)
        elif base.isdigit():
            value = int(base)
            if "/" in part:
                start, end = value, hi  # "n/step" means n..hi stepped
            else:
                if not (lo <= value <= hi):
                    raise ValueError(f"cron value {value} out of range {lo}-{hi}")
                values.add(value)
                continue
        else:
            raise ValueError(f"invalid cron field element {part!r}")
        if start < lo or end > hi or start > end:
            raise ValueError(f"cron range out of bounds: {part!r}")
        values.update(range(start, end + 1, step))
    if not values:
        raise ValueError("cron field matches no values")
    return values, restricted


def _resolve_spec(spec: str) -> Dict[str, Any]:
    """Expand aliases and detect one-shots; returns ``{"is_once", "expr"}``."""
    spec = str(spec or "").strip()
    if not spec:
        raise ValueError("a schedule needs a spec")
    if spec.lower() in ALIASES:
        return {"is_once": False, "expr": ALIASES[spec.lower()]}
    if spec.startswith("once:"):
        return {"is_once": True, "expr": spec[5:].strip()}
    return {"is_once": False, "expr": spec}


def _dom_dow_ok(dt: datetime, doms, dows, dom_restricted: bool, dow_restricted: bool) -> bool:
    dom_ok = dt.day in doms
    dow_ok = (dt.weekday() + 1) % 7 in dows  # cron 0=Sunday..6=Saturday
    if dom_restricted and dow_restricted:
        return dom_ok or dow_ok  # classic cron OR rule
    return dom_ok and dow_ok


def _advance_month(dt: datetime) -> datetime:
    if dt.month == 12:
        return dt.replace(year=dt.year + 1, month=1, day=1, hour=0, minute=0)
    return dt.replace(month=dt.month + 1, day=1, hour=0, minute=0)


def next_after(spec: str, after: Any, tz_name: str = "UTC") -> Optional[datetime]:
    """Next aware-UTC firing time strictly after ``after``, or ``None``.

    Returns ``None`` when the spec is a consumed one-shot, or when no time in
    the two-year horizon satisfies it (e.g. ``0 0 31 2 *``).  Raises
    :class:`ValueError` for a malformed spec.
    """
    after = _as_utc(after)
    resolved = _resolve_spec(spec)
    if resolved["is_once"]:
        target = _parse_once(resolved["expr"], tz_name)
        return target if target > after else None

    fields = resolved["expr"].split()
    if len(fields) != 5:
        raise ValueError("cron spec must have 5 fields: minute hour day month weekday")
    minutes, _ = _parse_field(fields[0], *_FIELD_BOUNDS[0])
    hours, _ = _parse_field(fields[1], *_FIELD_BOUNDS[1])
    doms, dom_restricted = _parse_field(fields[2], *_FIELD_BOUNDS[2])
    months, _ = _parse_field(fields[3], *_FIELD_BOUNDS[3])
    dows, dow_restricted = _parse_field(fields[4], *_FIELD_BOUNDS[4])
    if 7 in dows:
        dows.discard(7)
        dows.add(0)

    tz = _tz(tz_name)
    local = after.astimezone(tz)
    dt = local.replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = local + timedelta(days=HORIZON_DAYS)
    # Field-aware forward scan: skip whole months/days/hours that cannot match
    # instead of stepping minute by minute, so even unsatisfiable specs are cheap.
    while dt <= limit:
        if dt.month not in months:
            dt = _advance_month(dt)
            continue
        if not _dom_dow_ok(dt, doms, dows, dom_restricted, dow_restricted):
            dt = dt.replace(hour=0, minute=0) + timedelta(days=1)
            continue
        if dt.hour not in hours:
            dt = dt.replace(minute=0) + timedelta(hours=1)
            continue
        if dt.minute not in minutes:
            dt += timedelta(minutes=1)
            continue
        return dt.astimezone(UTC)
    return None


def validate_spec(spec: str, tz_name: str = "UTC") -> None:
    """Raise :class:`ValueError` if the spec is malformed or can never fire."""
    resolved = _resolve_spec(spec)
    if resolved["is_once"]:
        _parse_once(resolved["expr"], tz_name)
        return
    if next_after(spec, now_utc(), tz_name) is None:
        raise ValueError("schedule spec never fires within the next two years")


def describe_spec(spec: str) -> str:
    """Short human description of a spec, for tables and audit metadata."""
    resolved = _resolve_spec(spec)
    if resolved["is_once"]:
        return f"once ({resolved['expr']})"
    return resolved["expr"]


class ScheduleService:
    """Owns the ``action_schedules`` table and fires due actions.

    ``actions`` is the shared :class:`pinoc.actions.ActionDispatcher`; the
    service enqueues through it so scheduled runs are indistinguishable from
    manual ones in the job and audit tables (they carry
    ``requested_by='scheduler'`` and a ``schedule_id`` parameter).
    """

    def __init__(self, db, actions, state=None, notifier=None, interval: int = 30) -> None:
        self.db = db
        self.actions = actions
        self.state = state
        self.notifier = notifier
        self.interval = max(5, int(interval))
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="pinoc-schedules", daemon=True)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if self.db is not None and self.actions is not None:
            self.thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout)

    def status(self) -> Dict[str, Any]:
        if self.db is None or not self.db.available:
            return {"running": self.thread.is_alive(), "schedules": 0, "active": 0, "paused": 0}
        total = self.db.scalar("SELECT COUNT(*) FROM action_schedules") or 0
        active = self.db.scalar(
            "SELECT COUNT(*) FROM action_schedules WHERE enabled=1 AND paused=0 AND next_run IS NOT NULL") or 0
        paused = self.db.scalar("SELECT COUNT(*) FROM action_schedules WHERE paused=1") or 0
        return {"running": self.thread.is_alive(), "schedules": total, "active": active, "paused": paused}

    # -- CRUD --------------------------------------------------------------
    def get(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        rows = self.db.rows("SELECT * FROM action_schedules WHERE schedule_id=?", (schedule_id,))
        return rows[0] if rows else None

    def list(self) -> list:
        return self.db.rows(
            "SELECT * FROM action_schedules ORDER BY paused ASC, "
            "CASE WHEN next_run IS NULL THEN 1 ELSE 0 END, next_run ASC, action ASC")

    def create(self, *, device_id: str, action: str, spec: str, target: Optional[str] = None,
               timezone: str = "UTC", requested_by: str, role: str = "administrator",
               source_ip: Optional[str] = None) -> Dict[str, Any]:
        if not device_id or not action or not str(spec).strip():
            raise ValueError("device_id, action and spec are required")
        device = self.state.device(device_id) if self.state is not None else None
        if device is None:
            raise ValueError("device not found")
        self.actions.definition(action)  # raises ActionError for an unknown action
        self._check_action_target(action, device, target)
        tz = str(timezone or "UTC")
        _tz(tz)  # raises for a bogus IANA zone
        validate_spec(spec, tz)
        now = now_utc()
        next_run = next_after(spec, now, tz)
        if next_run is None:
            raise ValueError("schedule spec never fires within the next two years")
        schedule_id = str(uuid.uuid4())
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO action_schedules(schedule_id,device_id,action,target,spec,timezone,"
            "enabled,paused,requested_by,created_at,updated_at,next_run,last_run,last_job_id,"
            "last_status,last_error,consecutive_failures) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (schedule_id, device_id, action, target, str(spec).strip(), tz, 1, 0,
             requested_by, stamp, stamp, next_run.isoformat(),
             None, None, None, None, 0),
        )
        self.actions.audit(requested_by, role, source_ip, device_id, "schedule.create",
                           target, {"action": action, "spec": str(spec).strip(), "timezone": tz},
                           "allowed", "succeeded")
        return self.get(schedule_id)

    def update(self, schedule_id: str, *, paused: Optional[bool] = None,
               spec: Optional[str] = None, target: Optional[str] = None,
               requested_by: str, role: str = "administrator",
               source_ip: Optional[str] = None) -> Dict[str, Any]:
        row = self.get(schedule_id)
        if row is None:
            raise ValueError("schedule not found")
        new_spec = str(spec).strip() if spec is not None else row["spec"]
        new_target = target if target is not None else row["target"]
        if spec is not None:
            _tz(row["timezone"])
            validate_spec(new_spec, row["timezone"])
        device = self.state.device(row["device_id"]) if self.state is not None else None
        if new_target is not None and device is not None:
            self._check_action_target(row["action"], device, new_target)
        new_paused = bool(paused) if paused is not None else bool(row["paused"])
        reset_failures = (paused is not None and not paused) or spec is not None
        failures = 0 if reset_failures else int(row["consecutive_failures"] or 0)
        was_paused = bool(row["paused"])
        if new_paused:
            next_run = None
        elif spec is not None or was_paused:
            # Resuming (or changing the spec) recomputes the next fire time; a
            # no-op save keeps the stored value.
            next_run = self._next_after(new_spec, row["timezone"])
        else:
            next_run = row["next_run"]
        stamp = utcnow()
        self.db.execute(
            "UPDATE action_schedules SET spec=?,target=?,paused=?,consecutive_failures=?,"
            "next_run=?,updated_at=? WHERE schedule_id=?",
            (new_spec, new_target, 1 if new_paused else 0, failures, next_run, stamp, schedule_id),
        )
        self.actions.audit(requested_by, role, source_ip, row["device_id"], "schedule.update",
                           new_target, {"action": row["action"], "spec": new_spec,
                                        "paused": new_paused}, "allowed", "succeeded")
        return self.get(schedule_id)

    def delete(self, schedule_id: str, *, requested_by: str,
               role: str = "administrator", source_ip: Optional[str] = None) -> bool:
        row = self.get(schedule_id)
        if row is None:
            return False
        self.db.execute("DELETE FROM action_schedules WHERE schedule_id=?", (schedule_id,))
        self.actions.audit(requested_by, role, source_ip, row["device_id"], "schedule.delete",
                           row["target"], {"action": row["action"], "spec": row["spec"]},
                           "allowed", "succeeded")
        return True

    def run_now(self, schedule_id: str, *, requested_by: str,
                role: str = "administrator", source_ip: Optional[str] = None) -> Dict[str, Any]:
        """Queue the schedule's action immediately (operator-triggered).

        Does not touch ``next_run`` or ``consecutive_failures``; it only records
        ``last_run`` / ``last_job_id`` so the UI can show the manual run.
        """
        row = self.get(schedule_id)
        if row is None:
            raise ValueError("schedule not found")
        try:
            job = self.actions.enqueue(row["action"], row["device_id"], row["target"],
                                       requested_by, role, source_ip, {"schedule_id": schedule_id})
        except ActionError as exc:
            raise ValueError(str(exc))
        self.actions.audit(requested_by, role, source_ip, row["device_id"], "schedule.run",
                           row["target"], {"action": row["action"], "job_id": job["job_id"]},
                           "allowed", "queued")
        self.db.execute(
            "UPDATE action_schedules SET last_run=?,last_job_id=?,last_status='queued',last_error=NULL "
            "WHERE schedule_id=?", (utcnow(), job["job_id"], schedule_id))
        return job

    # -- engine ------------------------------------------------------------
    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                LOG.exception("schedule tick failed")
            self.stop_event.wait(self.interval)

    def tick(self) -> None:
        if self.db is None or self.actions is None or not self.db.available:
            return
        self._reconcile()
        self._fire_due()

    def _reconcile(self) -> None:
        """Learn the terminal outcome of jobs we previously enqueued."""
        rows = self.db.rows(
            "SELECT * FROM action_schedules WHERE last_job_id IS NOT NULL "
            "AND last_status IS NOT NULL AND last_status NOT IN ('succeeded','failed','timed_out','cancelled')")
        if not rows:
            return
        ids = [r["last_job_id"] for r in rows]
        marks = ",".join("?" * len(ids))
        jobs = {j["job_id"]: j for j in self.db.rows(
            f"SELECT job_id,status,error FROM action_jobs WHERE job_id IN ({marks})", ids)}
        now = now_utc()
        for row in rows:
            job = jobs.get(row["last_job_id"])
            if job is None or job["status"] in ("queued", "running"):
                continue
            status = job["status"]
            failures = int(row["consecutive_failures"] or 0)
            is_once = str(row["spec"]).startswith("once:")
            if status == "succeeded":
                failures, paused, error = 0, 0, None
            else:
                failures += 1
                paused = 1 if (is_once or failures >= MAX_CONSECUTIVE_FAILURES) else 0
                error = str(redact(job.get("error") or status))[:500]
            if paused and status != "succeeded":
                self._emit_failure(row, error)
            self.db.execute(
                "UPDATE action_schedules SET last_status=?,last_error=?,consecutive_failures=?,"
                "paused=?,next_run=?,updated_at=? WHERE schedule_id=?",
                (status, error, failures, paused, self._next_after(row["spec"], row["timezone"],
                                                                    only_if_not_once=is_once),
                 utcnow(), row["schedule_id"]),
            )
            self.actions.audit("scheduler", "administrator", None, row["device_id"],
                               "schedule.result", row["target"],
                               {"action": row["action"], "job_id": row["last_job_id"],
                                "status": status}, "allowed", status)

    def _fire_due(self) -> None:
        now = now_utc()
        rows = self.db.rows(
            "SELECT * FROM action_schedules WHERE enabled=1 AND paused=0 AND next_run IS NOT NULL")
        for row in rows:
            try:
                next_run = _as_utc(row["next_run"])
            except ValueError:
                continue
            if next_run <= now:
                self._dispatch_one(row, now)

    def _dispatch_one(self, row: Dict[str, Any], now: datetime) -> None:
        schedule_id = row["schedule_id"]
        tz = row["timezone"] or "UTC"
        is_once = str(row["spec"]).startswith("once:")
        failures = int(row["consecutive_failures"] or 0)
        error = None
        try:
            job = self.actions.enqueue(row["action"], row["device_id"], row["target"],
                                       "scheduler", "administrator", None,
                                       {"schedule_id": schedule_id})
        except ActionError as exc:
            job, error = None, str(redact(exc))[:500]
        except Exception as exc:  # noqa: BLE001 - never let one schedule kill the tick
            job, error = None, str(redact(exc))[:500]

        if job is None:
            failures += 1
            # A dispatch failure (offline device, no-longer-approved target,
            # ...) always retries after RETRY_MINUTES, one-shot schedules
            # included -- only MAX_CONSECUTIVE_FAILURES consecutive dispatch
            # failures actually pause the schedule.
            paused = 1 if failures >= MAX_CONSECUTIVE_FAILURES else 0
            if paused:
                next_run = None
            else:
                next_run = (now + timedelta(minutes=RETRY_MINUTES)).isoformat()
            if paused:
                self._emit_failure(row, error)
            self.db.execute(
                "UPDATE action_schedules SET last_run=?,last_status='dispatch_failed',"
                "last_error=?,consecutive_failures=?,paused=?,next_run=?,updated_at=? "
                "WHERE schedule_id=?",
                (now.isoformat(), error, failures, paused, next_run, utcnow(), schedule_id))
            self.actions.audit("scheduler", "administrator", None, row["device_id"],
                               "schedule.fire", row["target"],
                               {"action": row["action"], "error": error}, "denied",
                               "failed", error=error)
        else:
            next_run = None if is_once else self._next_after(row["spec"], tz)
            self.db.execute(
                "UPDATE action_schedules SET last_run=?,last_job_id=?,last_status='queued',"
                "last_error=NULL,paused=0,next_run=?,updated_at=? WHERE schedule_id=?",
                (now.isoformat(), job["job_id"], next_run, utcnow(), schedule_id))
            self.actions.audit("scheduler", "administrator", None, row["device_id"],
                               "schedule.fire", row["target"],
                               {"action": row["action"], "job_id": job["job_id"]},
                               "allowed", "queued")

    def _next_after(self, spec: str, tz: str, only_if_not_once: bool = False) -> Optional[str]:
        try:
            target = next_after(spec, now_utc(), tz or "UTC")
        except ValueError:
            return None
        if target is None and only_if_not_once:
            return None
        return target.isoformat() if target is not None else None

    def _emit_failure(self, row: Dict[str, Any], error: Optional[str]) -> None:
        device_id = row["device_id"]
        message = (f"Scheduled {row['action']} on {device_id} paused after repeated failures"
                   + (f": {error}" if error else ""))[:500]
        metadata = {"schedule_id": row["schedule_id"], "action": row["action"],
                    "spec": row["spec"]}
        self.db.execute(
            "INSERT INTO events(timestamp,device_id,event_type,severity,message,metadata_json) "
            "VALUES(?,?,?,?,?,?)",
            (utcnow(), device_id, "schedule_failed", "critical", message,
             json.dumps(metadata)))
        if self.notifier is not None and getattr(self.notifier, "enabled", False):
            try:
                self.notifier.enqueue("open", {
                    "severity": "critical", "alert_type": "schedule_failed",
                    "message": message, "device_id": device_id,
                })
            except Exception:  # noqa: BLE001 - notification must not break the tick
                LOG.exception("schedule failure notification failed")

    # -- validation helper -------------------------------------------------
    def _check_action_target(self, action: str, device: Dict[str, Any],
                             target: Optional[str]) -> None:
        """Static target/approval checks that do not depend on live online state.

        Mirrors :meth:`pinoc.actions.ActionDispatcher.validate` minus the
        online/conflict checks, so a schedule can be created for a device that
        is currently offline (the schedule targets the future).
        """
        if target is None:
            return
        if action.startswith("service."):
            if not UNIT.fullmatch(target) or target not in (device.get("manageable_services") or []):
                raise ValueError("service is not approved for management on this device")
        elif action == "package.check":
            if action not in (device.get("allowed_actions") or []):
                raise ValueError("package metadata checks are not approved for this device")
        elif action in RESCUE_ACTIONS:
            if action not in (device.get("allowed_actions") or []):
                raise ValueError("this recovery action is not approved for this device")
            if action == "logs.truncate" and not valid_log_path(target, device.get("important_paths") or []):
                raise ValueError("log path must be under /var/log or a declared important path")
            if action == "journal.vacuum" and not VACUUM_SPEC_RE.fullmatch(str(target)):
                raise ValueError("journal vacuum target must be like size:100M or time:7d")
