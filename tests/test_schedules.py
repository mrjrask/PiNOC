"""Coverage for the cron-style action scheduler (pinoc/schedules.py).

Three layers are exercised:

* :class:`CronTest` -- pure parsing / next-fire-time logic (no DB, no threads);
* :class:`EngineTest` -- the service against a real database with a fake
  ActionDispatcher (create/update/delete/run, firing, reconcile, failure ->
  auto-pause, one-shots, status, lifecycle);
* :class:`WebTest` -- the HTTP surface and its auth matrix through ``create_app``.
"""
import json
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from pinoc.actions import ActionError
from pinoc.database import Database, utcnow
from pinoc.models import DeviceState
from pinoc.schedules import (
    ALIASES,
    MAX_CONSECUTIVE_FAILURES,
    ScheduleService,
    next_after,
    _parse_field,
    validate_spec,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


def _make_device(**overrides) -> DeviceState:
    values = dict(id="pi", hostname="pi", friendly_name="Pi", online=True,
                  address="host", collection_method="ssh", ssh_user="pi",
                  ssh_port=22, manageable_services=["demo.service"],
                  allowed_actions=["package.check", "apt.clean"],
                  important_paths=["/srv/data"])
    values.update(overrides)
    return DeviceState(**values)


class Coordinator:
    def refresh_device(self, d):
        pass

    def refresh(self):
        pass


class _Notifier:
    enabled = True

    def __init__(self):
        self.queued = []

    def enqueue(self, transition, alert, device_name=None):
        self.queued.append((transition, alert))


class _FakeActions:
    """Stands in for ActionDispatcher in engine tests.

    ``fail`` makes the next ``fail`` enqueue() calls raise (simulating a
    dispatch failure such as an offline device).  Enqueues insert a real row in
    ``action_jobs`` so the reconcile path can observe terminal outcomes.
    """

    def __init__(self, db, registry=None, fail=0):
        self.db = db
        self.registry = registry or {a: object() for a in (
            "device.refresh", "device.reboot", "service.restart",
            "package.check", "apt.clean", "logs.truncate")}
        self.fail = fail
        self.enqueued = []
        self.audits = []

    def definition(self, action):
        if action not in self.registry:
            raise ActionError("unsupported action")
        return self.registry[action]

    def enqueue(self, action, device_id, target, actor, role,
                source_ip=None, parameters=None):
        self.definition(action)
        if self.fail:
            self.fail -= 1
            raise ActionError("device is offline")
        job_id = str(uuid.uuid4())
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO action_jobs(job_id,device_id,action,target,parameters_json,"
            "requested_by,requested_role,source_ip,requested_at,status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (job_id, device_id, action, target, json.dumps(parameters or {}),
             actor, role, source_ip, stamp, "queued"))
        job = {"job_id": job_id, "action": action, "device_id": device_id,
               "target": target, "status": "queued"}
        self.enqueued.append(job)
        return job

    def audit(self, user, role, ip, device, action, target, params, auth,
              result=None, exit_code=None, duration=None, error=None):
        self.audits.append({"user": user, "device": device, "action": action,
                            "auth": auth, "result": result, "error": error})


def _insert_schedule(db, **values):
    row = dict(schedule_id=str(uuid.uuid4()), device_id="pi", action="device.refresh",
               target=None, spec="* * * * *", timezone="UTC", enabled=1, paused=0,
               requested_by="test", created_at=utcnow(), updated_at=utcnow(),
               next_run=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
               last_run=None, last_job_id=None, last_status=None, last_error=None,
               consecutive_failures=0)
    row.update(values)
    db.execute(
        "INSERT INTO action_schedules(schedule_id,device_id,action,target,spec,timezone,"
        "enabled,paused,requested_by,created_at,updated_at,next_run,last_run,last_job_id,"
        "last_status,last_error,consecutive_failures) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row["schedule_id"], row["device_id"], row["action"], row["target"], row["spec"],
         row["timezone"], row["enabled"], row["paused"], row["requested_by"],
         row["created_at"], row["updated_at"], row["next_run"], row["last_run"],
         row["last_job_id"], row["last_status"], row["last_error"],
         row["consecutive_failures"]))
    return row["schedule_id"]


# ---------------------------------------------------------------------------
# Cron parsing / next-fire logic
# ---------------------------------------------------------------------------
class CronTest(unittest.TestCase):
    BASE = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)  # a Sunday

    def _next(self, spec, tz="UTC", after=None):
        return next_after(spec, after or self.BASE, tz)

    def test_daily(self):
        self.assertEqual(self._next("0 3 * * *"),
                         datetime(2026, 9, 21, 3, 0, tzinfo=UTC))

    def test_step(self):
        self.assertEqual(self._next("*/15 * * * *"),
                         datetime(2026, 9, 20, 12, 15, tzinfo=UTC))

    def test_weekday(self):
        self.assertEqual(self._next("0 0 * * 0"),   # Sunday; BASE is Sunday
                         datetime(2026, 9, 27, 0, 0, tzinfo=UTC))
        self.assertEqual(self._next("0 12 13 * 3"),  # Wednesday
                         datetime(2026, 9, 23, 12, 0, tzinfo=UTC))

    def test_month_day(self):
        self.assertEqual(self._next("30 6 1 * *"),
                         datetime(2026, 10, 1, 6, 30, tzinfo=UTC))

    def test_alias(self):
        self.assertEqual(self._next("@daily"), self._next(ALIASES["@daily"]))
        self.assertEqual(self._next("@hourly"), datetime(2026, 9, 20, 13, 0, tzinfo=UTC))

    def test_timezone(self):
        # 03:00 America/New_York in September is EDT (UTC-4) => 07:00 UTC.
        self.assertEqual(self._next("0 3 * * *", tz="America/New_York"),
                         datetime(2026, 9, 21, 7, 0, tzinfo=UTC))

    def test_once_future(self):
        self.assertEqual(self._next("once:2026-09-25T08:30"),
                         datetime(2026, 9, 25, 8, 30, tzinfo=UTC))

    def test_once_past_is_none(self):
        self.assertIsNone(self._next("once:2026-01-01T00:00"))

    def test_unsatisfiable_is_none(self):
        self.assertIsNone(self._next("0 0 31 2 *"))  # Feb 31

    def test_leap_only_fires(self):
        self.assertEqual(self._next("0 0 29 2 *"),
                         datetime(2028, 2, 29, 0, 0, tzinfo=UTC))

    def test_malformed_raises(self):
        for bad in ("* * * *", "61 * * * *", "* 24 * * *", "* * 0 * *",
                    "* * * 13 *", "* * * * 8", "a b c d e"):
            with self.assertRaises(ValueError, msg=bad):
                self._next(bad)

    def test_parse_field_edges(self):
        self.assertEqual(sorted(_parse_field("*/2", 0, 59)[0]),
                         list(range(0, 60, 2)))
        self.assertEqual(_parse_field("5-10/2", 0, 59)[0], {5, 7, 9})
        self.assertEqual(_parse_field("1,15,30", 0, 59)[0], {1, 15, 30})
        self.assertFalse(_parse_field("*", 0, 59)[1])   # wildcard: not restricted
        self.assertTrue(_parse_field("*/2", 0, 59)[1])  # step: restricted
        for bad in ("61", "*/0", "", "a-b", "2-1"):
            with self.assertRaises(ValueError):
                _parse_field(bad, 0, 59)

    def test_validate_spec(self):
        validate_spec("0 3 * * *")
        validate_spec("@daily")
        validate_spec("once:2026-12-01T00:00")
        with self.assertRaises(ValueError):
            validate_spec("0 0 31 2 *")
        with self.assertRaises(ValueError):
            validate_spec("once:not-a-date")


# ---------------------------------------------------------------------------
# Service engine
# ---------------------------------------------------------------------------
class EngineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([_make_device()], replace=True)
        self.fake = _FakeActions(self.db)
        self.notifier = _Notifier()
        self.svc = ScheduleService(self.db, self.fake, state=self.state,
                                   notifier=self.notifier, interval=30)

    def _row(self, schedule_id):
        return self.svc.get(schedule_id)

    # -- CRUD --------------------------------------------------------------
    def test_create_persists_and_audits(self):
        s = self.svc.create(device_id="pi", action="device.refresh", spec="@daily",
                            requested_by="admin")
        self.assertIsNotNone(s["schedule_id"])
        self.assertFalse(s["paused"])
        self.assertIsNotNone(s["next_run"])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM action_schedules"), 1)
        self.assertTrue(any(a["action"] == "schedule.create" for a in self.fake.audits))

    def test_create_rejects_unknown_action(self):
        with self.assertRaises(ActionError):
            self.svc.create(device_id="pi", action="nope.action", spec="@daily",
                            requested_by="admin")

    def test_create_rejects_unknown_device(self):
        with self.assertRaises(ValueError):
            self.svc.create(device_id="ghost", action="device.refresh", spec="@daily",
                            requested_by="admin")

    def test_create_rejects_malformed_and_never_firing(self):
        with self.assertRaises(ValueError):
            self.svc.create(device_id="pi", action="device.refresh", spec="* * * *",
                            requested_by="admin")
        with self.assertRaises(ValueError):
            self.svc.create(device_id="pi", action="device.refresh", spec="0 0 31 2 *",
                            requested_by="admin")

    def test_create_rejects_unapproved_rescue_target(self):
        self.state.publish([_make_device(allowed_actions=["package.check"])], replace=True)
        with self.assertRaises(ValueError):
            self.svc.create(device_id="pi", action="logs.truncate", spec="@daily",
                            target="/etc/passwd", requested_by="admin")

    def test_update_pause_resume_and_spec(self):
        s = self.svc.create(device_id="pi", action="device.refresh", spec="@daily",
                            requested_by="admin")
        sid = s["schedule_id"]
        paused = self.svc.update(sid, paused=True, requested_by="admin")
        self.assertTrue(paused["paused"])
        self.assertIsNone(paused["next_run"])
        resumed = self.svc.update(sid, paused=False, requested_by="admin")
        self.assertFalse(resumed["paused"])
        self.assertIsNotNone(resumed["next_run"])
        changed = self.svc.update(sid, spec="0 4 * * *", requested_by="admin")
        self.assertEqual(changed["spec"], "0 4 * * *")
        self.assertEqual(changed["consecutive_failures"], 0)  # reset on spec change

    def test_update_missing_raises(self):
        with self.assertRaises(ValueError):
            self.svc.update("does-not-exist", paused=True, requested_by="admin")

    def test_delete(self):
        s = self.svc.create(device_id="pi", action="device.refresh", spec="@daily",
                            requested_by="admin")
        self.assertTrue(self.svc.delete(s["schedule_id"], requested_by="admin"))
        self.assertFalse(self.svc.delete(s["schedule_id"], requested_by="admin"))
        self.assertIsNone(self.svc.get(s["schedule_id"]))

    def test_run_now_queues_without_touching_next_run(self):
        s = self.svc.create(device_id="pi", action="device.refresh", spec="@daily",
                            requested_by="admin")
        before = s["next_run"]
        job = self.svc.run_now(s["schedule_id"], requested_by="admin")
        row = self._row(s["schedule_id"])
        self.assertEqual(row["last_job_id"], job["job_id"])
        self.assertEqual(row["next_run"], before)  # manual run does not reschedule
        self.assertEqual(row["consecutive_failures"], 0)

    # -- firing ------------------------------------------------------------
    def test_fire_due_enqueues_and_reschedules(self):
        sid = _insert_schedule(self.db, spec="0 3 * * *")
        self.svc._fire_due()
        self.assertEqual(len(self.fake.enqueued), 1)
        row = self._row(sid)
        self.assertEqual(row["last_status"], "queued")
        self.assertIsNotNone(row["next_run"])
        self.assertGreater(row["next_run"], utcnow())  # advanced past now

    def test_not_due_does_not_fire(self):
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        _insert_schedule(self.db, next_run=future)
        self.svc._fire_due()
        self.assertEqual(self.fake.enqueued, [])

    # -- dispatch failure -> retry -> auto-pause ---------------------------
    def test_dispatch_failure_retries_then_pauses(self):
        # One schedule that keeps failing: the per-schedule counter must
        # accumulate across failures until the schedule auto-pauses.
        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        sid = _insert_schedule(self.db)
        self.fake.fail = MAX_CONSECUTIVE_FAILURES  # every dispatch attempt fails
        for _ in range(MAX_CONSECUTIVE_FAILURES - 1):
            self.db.execute("UPDATE action_schedules SET next_run=? WHERE schedule_id=?",
                            (past, sid))
            self.svc._fire_due()
            row = self._row(sid)
            self.assertEqual(row["last_status"], "dispatch_failed")
            self.assertLess(row["consecutive_failures"], MAX_CONSECUTIVE_FAILURES)
            self.assertFalse(row["paused"])
            self.assertIsNotNone(row["next_run"])  # short retry, not paused

        self.db.execute("UPDATE action_schedules SET next_run=? WHERE schedule_id=?",
                        (past, sid))
        self.svc._fire_due()
        row = self._row(sid)
        self.assertEqual(row["consecutive_failures"], MAX_CONSECUTIVE_FAILURES)
        self.assertTrue(row["paused"])
        self.assertIsNone(row["next_run"])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 1)
        event = self.db.rows("SELECT * FROM events")[0]
        self.assertEqual(event["event_type"], "schedule_failed")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(len(self.notifier.queued), 1)

    # -- reconcile ---------------------------------------------------------
    def test_reconcile_success_resets_failures(self):
        sid = _insert_schedule(self.db, consecutive_failures=2)
        job = self.fake.enqueue("device.refresh", "pi", None, "scheduler",
                                "administrator", None, {"schedule_id": sid})
        self.db.execute("UPDATE action_schedules SET last_job_id=?,last_status='queued' "
                        "WHERE schedule_id=?", (job["job_id"], sid))
        self.db.execute("UPDATE action_jobs SET status='succeeded',completed_at=? "
                        "WHERE job_id=?", (utcnow(), job["job_id"]))
        self.svc._reconcile()
        row = self._row(sid)
        self.assertEqual(row["last_status"], "succeeded")
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertFalse(row["paused"])

    def test_reconcile_failure_increments_and_pauses_at_max(self):
        sid = _insert_schedule(self.db, consecutive_failures=MAX_CONSECUTIVE_FAILURES - 1)
        job = self.fake.enqueue("device.refresh", "pi", None, "scheduler",
                                "administrator", None, {"schedule_id": sid})
        # The engine records last_status='queued' when firing; reconcile picks
        # up non-terminal statuses and applies the terminal job outcome.
        self.db.execute("UPDATE action_schedules SET last_job_id=?,last_status='queued' "
                        "WHERE schedule_id=?", (job["job_id"], sid))
        self.db.execute("UPDATE action_jobs SET status='failed',error='boom',completed_at=? "
                        "WHERE job_id=?", (utcnow(), job["job_id"]))
        self.svc._reconcile()
        row = self._row(sid)
        self.assertEqual(row["consecutive_failures"], MAX_CONSECUTIVE_FAILURES)
        self.assertTrue(row["paused"])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM events"), 1)

    def test_reconcile_ignores_non_terminal(self):
        sid = _insert_schedule(self.db)
        job = self.fake.enqueue("device.refresh", "pi", None, "scheduler",
                                "administrator", None, {"schedule_id": sid})
        self.db.execute("UPDATE action_schedules SET last_job_id=?,last_status='running' "
                        "WHERE schedule_id=?", (job["job_id"], sid))
        self.db.execute("UPDATE action_jobs SET status='running' WHERE job_id=?",
                        (job["job_id"],))
        self.svc._reconcile()
        self.assertEqual(self._row(sid)["last_status"], "running")  # unchanged

    # -- one-shots ---------------------------------------------------------
    def test_once_consumed_after_fire(self):
        future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        sid = _insert_schedule(self.db, spec="once:2027-01-01T00:00", next_run=future)
        self.db.execute("UPDATE action_schedules SET next_run=? WHERE schedule_id=?",
                        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), sid))
        self.svc._fire_due()
        row = self._row(sid)
        self.assertEqual(row["last_status"], "queued")
        self.assertIsNone(row["next_run"])  # a one-shot never fires again

    # -- status / lifecycle ------------------------------------------------
    def test_status_counts(self):
        self.svc.create(device_id="pi", action="device.refresh", spec="@daily",
                        requested_by="admin")
        self.svc.create(device_id="pi", action="package.check", spec="@weekly",
                        requested_by="admin")
        first = self.svc.list()[0]["schedule_id"]
        self.svc.update(first, paused=True, requested_by="admin")
        status = self.svc.status()
        self.assertEqual(status["schedules"], 2)
        self.assertEqual(status["paused"], 1)
        self.assertEqual(status["active"], 1)
        self.assertFalse(status["running"])  # thread never started in this test

    def test_start_stop(self):
        self.svc.start()
        self.assertTrue(self.svc.thread.is_alive())
        self.assertTrue(self.svc.status()["running"])
        self.svc.stop(timeout=5)
        self.assertFalse(self.svc.thread.is_alive())
        self.svc.tick()  # still safe after stop


# ---------------------------------------------------------------------------
# Web surface + auth matrix
# ---------------------------------------------------------------------------
class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        from pinoc.actions import ActionDispatcher
        from pinoc.history import HistoryManager
        from pinoc.security import SecurityManager
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([_make_device()], replace=True)
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True,
                         "SECRET_KEY": "test-secret", "DATABASE": self.db},
            self.history, Coordinator())
        self.app.extensions["pinoc_actions"].runner = (
            lambda args, **kw: subprocess.CompletedProcess(args, 0, "", ""))
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        self.security.create_user("boss", "pw12345678", "administrator")
        self.security.create_user("op", "pw12345678", "operator")
        self.security.create_user("watch", "pw12345678", "viewer")
        self.svc = ScheduleService(self.db, self.app.extensions["pinoc_actions"],
                                   state=self.state)
        self.svc.start()
        self.app.extensions["pinoc_schedules"] = self.svc
        self.client = self.app.test_client()

    def tearDown(self):
        self.svc.stop()
        self.app.extensions["pinoc_actions"].stop()

    def _login(self, username):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post("/login", data={"username": username,
                                                "password": "pw12345678", "csrf_token": csrf})

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path, body=None):
        return self.client.post(path, json=body or {},
                                headers={"X-CSRF-Token": self._csrf()})

    def _put(self, path, body=None):
        return self.client.put(path, json=body or {},
                               headers={"X-CSRF-Token": self._csrf()})

    def _delete(self, path):
        return self.client.delete(path, headers={"X-CSRF-Token": self._csrf()})

    def test_admin_full_crud(self):
        self.assertEqual(self._login("boss").status_code, 302)
        created = self._post("/api/schedules",
                             {"device_id": "pi", "action": "device.refresh",
                              "spec": "@daily"})
        self.assertEqual(created.status_code, 201)
        sid = created.get_json()["schedule"]["schedule_id"]

        listing = self.client.get("/api/schedules")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.get_json()["schedules"]), 1)
        self.assertIsNotNone(listing.get_json()["status"])

        updated = self._put(f"/api/schedules/{sid}", {"paused": True})
        self.assertEqual(updated.status_code, 200)
        self.assertTrue(updated.get_json()["schedule"]["paused"])

        run = self._post(f"/api/schedules/{sid}/run")
        self.assertEqual(run.status_code, 202)
        self.assertIn("job_id", run.get_json()["job"])

        removed = self._delete(f"/api/schedules/{sid}")
        self.assertEqual(removed.status_code, 200)
        self.assertEqual(self._delete(f"/api/schedules/{sid}").status_code, 404)

    def test_create_validation_errors(self):
        self.assertEqual(self._login("boss").status_code, 302)
        self.assertEqual(self._post("/api/schedules",
                                    {"device_id": "ghost", "action": "device.refresh",
                                     "spec": "@daily"}).status_code, 400)
        self.assertEqual(self._post("/api/schedules",
                                    {"device_id": "pi", "action": "device.refresh",
                                     "spec": "* * * *"}).status_code, 400)
        self.assertEqual(self._post("/api/schedules",
                                    {"device_id": "pi", "action": "nope.action",
                                     "spec": "@daily"}).status_code, 400)

    def test_operator_denied(self):
        self.assertEqual(self._login("op").status_code, 302)
        self.assertEqual(self.client.get("/api/schedules").status_code, 403)
        self.assertEqual(self._post("/api/schedules",
                                    {"device_id": "pi", "action": "device.refresh",
                                     "spec": "@daily"}).status_code, 403)

    def test_viewer_denied(self):
        self.assertEqual(self._login("watch").status_code, 302)
        self.assertEqual(self.client.get("/api/schedules").status_code, 403)

    def test_unauthenticated_is_401(self):
        self.assertEqual(self.client.get("/api/schedules").status_code, 401)
        self.assertEqual(self._post("/api/schedules",
                                    {"device_id": "pi", "action": "device.refresh",
                                     "spec": "@daily"}).status_code, 401)

    def test_token_scopes(self):
        admin_token = self.security.create_token("boss", ["admin:config"])
        read_token = self.security.create_token("boss", ["read:fleet"])
        ok = self.client.get("/api/schedules",
                             headers={"Authorization": "Bearer " + admin_token})
        self.assertEqual(ok.status_code, 200)
        denied = self.client.get("/api/schedules",
                                 headers={"Authorization": "Bearer " + read_token})
        self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
