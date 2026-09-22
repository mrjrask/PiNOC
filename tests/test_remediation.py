"""Coverage for automatic playbook remediation (pinoc/remediation.py).

Three layers are exercised, matching tests/test_schedules.py's split:

* :class:`EngineTest` -- the service's bookkeeping (cooldown, max-attempts,
  maintenance deferral, approve/deny, auto-resolve reset) against a real
  database with a fake ActionDispatcher, so timing is fully deterministic;
* :class:`RealDispatcherTest` -- one end-to-end run against a genuine
  ``ActionDispatcher`` (stubbed subprocess runner) proving remediation
  enqueues through the *real* action queue and audit trail, not a parallel
  mechanism;
* :class:`WebTest` -- the HTTP surface (alert payload, list, approve/deny)
  and its auth matrix through ``create_app``.
"""
import json
import subprocess
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from pinoc.actions import ActionDispatcher, ActionError
from pinoc.database import Database, utcnow
from pinoc.models import DeviceState
from pinoc.playbooks import load_playbooks
from pinoc.remediation import RemediationService
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


def iso(seconds_ago: float = 0) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()


def make_device(**overrides) -> DeviceState:
    values = dict(id="pi", hostname="pi", friendly_name="Pi", online=True, address="host",
                  collection_method="ssh", ssh_user="pi", ssh_port=22,
                  manageable_services=["demo.service"], allowed_actions=["journal.vacuum"],
                  important_paths=[])
    values.update(overrides)
    return DeviceState(**values)


def auto_playbook(**overrides):
    entry = {"id": "service-failed", "alert_type": "service_failed", "title": "Service failed",
             "markdown": "x", "actions": ["service.restart"],
             "remediation": {"action": "service.restart", "policy": "auto",
                              "cooldown_seconds": 300, "max_attempts": 2}}
    entry["remediation"].update(overrides.pop("remediation", {}))
    entry.update(overrides)
    return entry


def approve_playbook(**overrides):
    entry = {"id": "disk-full", "alert_type": "critical_disk_usage", "title": "Disk full",
             "markdown": "x", "actions": [],
             "remediation": {"action": "journal.vacuum", "target": "time:3d", "policy": "approve",
                              "cooldown_seconds": 300, "max_attempts": 2}}
    entry["remediation"].update(overrides.pop("remediation", {}))
    entry.update(overrides)
    return entry


class _FakeActions:
    """Stands in for ActionDispatcher; enqueue() writes a real action_jobs
    row (so status queries work) without running anything asynchronously.
    ``fail`` makes the next N enqueue() calls raise (a dispatch failure)."""

    def __init__(self, db, fail=0):
        self.db = db
        self.fail = fail
        self.enqueued = []
        self.audits = []

    def enqueue(self, action, device_id, target, actor, role, source_ip=None, parameters=None):
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
        self.audits.append({"user": user, "role": role, "device": device, "action": action,
                            "target": target, "auth": auth, "result": result, "error": error})


class EngineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([make_device()], replace=True)
        self.actions = _FakeActions(self.db)

    def _seed_alert(self, alert_type="service_failed", resource="demo.service", device_id="pi"):
        fp = f"{device_id}:{alert_type}:{resource}"
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,"
            "state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (device_id, alert_type, "warning", f"{alert_type} happened", fp, iso(30), iso(1),
             "active", json.dumps({"resource": resource})))
        return fp

    def _resolve_alert(self, fingerprint):
        self.db.execute("UPDATE alerts SET resolved_at=?,state='resolved' WHERE fingerprint=?",
                        (utcnow(), fingerprint))

    def _svc(self, raw_playbooks):
        # Route through load_playbooks() so the remediation block picks up
        # its schema defaults (respect_maintenance, ...) exactly as the real
        # config loader would fill them in.
        playbooks = load_playbooks({"playbooks": raw_playbooks})
        self.assertEqual(len(playbooks), len(raw_playbooks), "a fixture playbook failed validation")
        return RemediationService(self.db, self.actions, state=self.state, playbooks=playbooks, interval=9999)

    def test_no_remediation_block_is_a_no_op(self):
        playbook = {"id": "service-failed", "alert_type": "service_failed", "title": "Service failed",
                    "markdown": "x", "actions": ["service.restart"]}
        fp = self._seed_alert()
        svc = self._svc([playbook])
        svc.tick()
        self.assertIsNone(svc.get(fp))
        self.assertEqual(self.actions.enqueued, [])

    def test_auto_run_happy_path_enqueues_through_action_queue(self):
        fp = self._seed_alert()
        svc = self._svc([auto_playbook()])
        svc.tick()
        self.assertEqual(len(self.actions.enqueued), 1)
        job = self.actions.enqueued[0]
        self.assertEqual(job["action"], "service.restart")
        self.assertEqual(job["device_id"], "pi")
        # The service target comes from the alert's fingerprint (the resource
        # embedded in it), not a hardcoded value.
        self.assertEqual(job["target"], "demo.service")
        row = svc.get(fp)
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["last_status"], "queued")
        self.assertEqual(row["last_job_id"], job["job_id"])
        self.assertIsNotNone(row["cooldown_until"])
        # Confirmed via the real action_jobs table, not just the fake's log.
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM action_jobs WHERE job_id=?", (job["job_id"],)), 1)

    def test_cooldown_blocks_a_second_attempt_within_the_window(self):
        self._seed_alert()
        svc = self._svc([auto_playbook(remediation={"cooldown_seconds": 600})])
        svc.tick()
        svc.tick()
        svc.tick()
        self.assertEqual(len(self.actions.enqueued), 1)

    def test_cooldown_elapsing_allows_the_next_attempt(self):
        fp = self._seed_alert()
        svc = self._svc([auto_playbook(remediation={"cooldown_seconds": 600})])
        svc.tick()
        # Simulate the cooldown window having elapsed.
        self.db.execute("UPDATE remediation_runs SET cooldown_until=? WHERE fingerprint=?",
                        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), fp))
        svc.tick()
        self.assertEqual(len(self.actions.enqueued), 2)
        self.assertEqual(svc.get(fp)["attempts"], 2)

    def test_max_attempts_enforced(self):
        fp = self._seed_alert()
        svc = self._svc([auto_playbook(remediation={"cooldown_seconds": 60, "max_attempts": 2})])
        for _ in range(5):
            svc.tick()
            self.db.execute("UPDATE remediation_runs SET cooldown_until=? WHERE fingerprint=?",
                            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), fp))
        self.assertEqual(len(self.actions.enqueued), 2)
        row = svc.get(fp)
        self.assertEqual(row["attempts"], 2)
        self.assertEqual(row["last_status"], "attempts_exhausted")

    def test_dispatch_failure_still_counts_as_an_attempt_and_is_audited(self):
        fp = self._seed_alert()
        self.actions.fail = 1
        svc = self._svc([auto_playbook()])
        svc.tick()
        row = svc.get(fp)
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["last_status"], "dispatch_failed")
        self.assertIsNone(row["last_job_id"])
        dispatch_audits = [a for a in self.actions.audits if a["action"] == "remediation.dispatch_failed"]
        self.assertEqual(len(dispatch_audits), 1)
        self.assertEqual(dispatch_audits[0]["result"], "failed")

    def test_maintenance_defers_without_spending_an_attempt(self):
        fp = self._seed_alert()
        self.state.publish([make_device(maintenance=True)], replace=True)
        svc = self._svc([auto_playbook()])
        svc.tick()
        svc.tick()
        self.assertEqual(self.actions.enqueued, [])
        row = svc.get(fp)
        self.assertEqual(row["attempts"], 0)
        self.assertEqual(row["last_status"], "deferred_maintenance")

    def test_maintenance_can_be_opted_out_of(self):
        self._seed_alert()
        self.state.publish([make_device(maintenance=True)], replace=True)
        svc = self._svc([auto_playbook(remediation={"respect_maintenance": False})])
        svc.tick()
        self.assertEqual(len(self.actions.enqueued), 1)

    def test_approve_policy_requests_approval_instead_of_running(self):
        fp = self._seed_alert("critical_disk_usage", "/")
        svc = self._svc([approve_playbook()])
        svc.tick()
        self.assertEqual(self.actions.enqueued, [])
        row = svc.get(fp)
        self.assertEqual(row["approval_status"], "pending")
        self.assertEqual([r["fingerprint"] for r in svc.pending_approvals()], [fp])
        requested = [a for a in self.actions.audits if a["action"] == "remediation.approval_requested"]
        self.assertEqual(len(requested), 1)
        # A second tick must not spam a fresh approval-requested audit entry.
        svc.tick()
        self.assertEqual(len([a for a in self.actions.audits if a["action"] == "remediation.approval_requested"]), 1)

    def test_decide_approve_enqueues_through_the_action_queue_and_audits(self):
        fp = self._seed_alert("critical_disk_usage", "/")
        svc = self._svc([approve_playbook()])
        svc.tick()
        row = svc.decide(fp, True, "alice", "administrator", "10.0.0.5")
        self.assertEqual(row["approval_status"], "approved")
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(len(self.actions.enqueued), 1)
        job = self.actions.enqueued[0]
        self.assertEqual(job["action"], "journal.vacuum")
        self.assertEqual(job["target"], "time:3d")
        approved = [a for a in self.actions.audits if a["action"] == "remediation.approved"]
        self.assertEqual(len(approved), 1)
        self.assertEqual(approved[0]["user"], "alice")

    def test_decide_deny_does_not_enqueue_and_stays_denied(self):
        fp = self._seed_alert("critical_disk_usage", "/")
        svc = self._svc([approve_playbook()])
        svc.tick()
        row = svc.decide(fp, False, "alice", "administrator")
        self.assertEqual(row["approval_status"], "denied")
        self.assertEqual(self.actions.enqueued, [])
        # A denied remediation must not be re-offered while the same alert stays open.
        svc.tick()
        self.assertEqual(self.actions.enqueued, [])
        self.assertEqual(svc.get(fp)["approval_status"], "denied")

    def test_decide_without_a_pending_request_raises(self):
        svc = self._svc([approve_playbook()])
        with self.assertRaises(ValueError):
            svc.decide("pi:critical_disk_usage:/", True, "alice")

    def test_auto_resolve_recovery_resets_bookkeeping(self):
        fp = self._seed_alert()
        svc = self._svc([auto_playbook()])
        svc.tick()
        self.assertEqual(svc.get(fp)["attempts"], 1)
        self._resolve_alert(fp)
        svc.tick()
        row = svc.get(fp)
        self.assertEqual(row["attempts"], 0)
        self.assertIsNone(row["cooldown_until"])
        self.assertIsNone(row["approval_status"])
        # A later recurrence of the same alert type gets a clean slate.
        self._seed_alert()
        svc.tick()
        self.assertEqual(len(self.actions.enqueued), 2)

    def test_resolve_while_approval_pending_cancels_it_and_is_audited(self):
        fp = self._seed_alert("critical_disk_usage", "/")
        svc = self._svc([approve_playbook()])
        svc.tick()
        self.assertEqual(svc.get(fp)["approval_status"], "pending")
        self._resolve_alert(fp)
        svc.tick()
        self.assertIsNone(svc.get(fp)["approval_status"])
        cancelled = [a for a in self.actions.audits if a["action"] == "remediation.cancelled"]
        self.assertEqual(len(cancelled), 1)


class RealDispatcherTest(unittest.TestCase):
    """One end-to-end pass through the genuine ActionDispatcher."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([make_device()], replace=True)
        self.dispatcher = ActionDispatcher(self.db, self.state, max_workers=1,
                                           runner=lambda args, **kw: subprocess.CompletedProcess(args, 0, "", ""))
        self.addCleanup(self.dispatcher.stop)

    def test_auto_remediation_runs_through_the_real_action_queue(self):
        fp = "pi:service_failed:demo.service"
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,"
            "state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            ("pi", "service_failed", "warning", "demo.service failed", fp, iso(30), iso(1),
             "active", json.dumps({"resource": "demo.service"})))
        svc = RemediationService(self.db, self.dispatcher, state=self.state,
                                 playbooks=load_playbooks({"playbooks": [auto_playbook()]}), interval=9999)
        svc.tick()
        job_id = svc.get(fp)["last_job_id"]
        self.assertIsNotNone(job_id)
        # Give the dispatcher's worker thread a moment to run the job through
        # to completion via the exact same code path a manual click uses.
        deadline = time.monotonic() + 5
        job = self.dispatcher.get(job_id)
        while job["status"] in ("queued", "running") and time.monotonic() < deadline:
            time.sleep(0.05)
            job = self.dispatcher.get(job_id)
        self.assertEqual(job["status"], "succeeded")
        # The run is indistinguishable from a manual one in the audit trail
        # except for who/what requested it.
        audit_rows = self.db.rows("SELECT * FROM audit_records WHERE device_id='pi' AND action='service.restart'")
        self.assertTrue(any(r["user"] == "remediation" for r in audit_rows))


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        from pinoc.history import HistoryManager
        from pinoc.security import SecurityManager
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([make_device()], replace=True)
        config = {"TESTING": True, "AUTH_ENABLED": True, "SECRET_KEY": "test-secret",
                  "DATABASE": self.db,
                  "PINOC_CONFIG": {"playbooks": [auto_playbook(), approve_playbook()]}}
        self.app = create_app(self.state, config, self.history, None)
        self.app.extensions["pinoc_actions"].runner = (
            lambda args, **kw: subprocess.CompletedProcess(args, 0, "", ""))
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        self.security.create_user("boss", "pw12345678", "administrator")
        self.security.create_user("op", "pw12345678", "operator")
        self.security.create_user("watch", "pw12345678", "viewer")
        self.svc = RemediationService(self.db, self.app.extensions["pinoc_actions"],
                                      state=self.state, playbooks=self.app.extensions["pinoc_playbooks"],
                                      interval=9999)
        self.app.extensions["pinoc_remediation"] = self.svc
        self.client = self.app.test_client()

    def tearDown(self):
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

    def _post(self, path):
        return self.client.post(path, headers={"X-CSRF-Token": self._csrf()})

    def _seed_alert(self, alert_type, resource):
        fp = f"pi:{alert_type}:{resource}"
        alert_id = self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,"
            "state,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            ("pi", alert_type, "warning", f"{alert_type} happened", fp, iso(30), iso(1),
             "active", json.dumps({"resource": resource})))
        return alert_id, fp

    def test_alerts_endpoint_surfaces_remediation_status(self):
        alert_id, fp = self._seed_alert("service_failed", "demo.service")
        self.svc.tick()
        self._login("op")
        alerts = self.client.get("/api/alerts").get_json()["alerts"]
        row = next(a for a in alerts if a["fingerprint"] == fp)
        self.assertIsNotNone(row["remediation"])
        self.assertEqual(row["remediation"]["attempts"], 1)

    def test_pending_approval_visible_and_viewer_cannot_decide(self):
        alert_id, fp = self._seed_alert("critical_disk_usage", "/")
        self.svc.tick()
        self._login("watch")
        pending = self.client.get("/api/remediations?state=pending").get_json()["remediations"]
        self.assertEqual([r["fingerprint"] for r in pending], [fp])
        self.assertEqual(self._post(f"/api/alerts/{alert_id}/remediation/approve").status_code, 403)

    def test_operator_can_approve_and_deny(self):
        alert_id, fp = self._seed_alert("critical_disk_usage", "/")
        self.svc.tick()
        self._login("op")
        response = self._post(f"/api/alerts/{alert_id}/remediation/approve")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["remediation"]["approval_status"], "approved")
        # Already decided; a second approve has nothing pending to act on.
        self.assertEqual(self._post(f"/api/alerts/{alert_id}/remediation/approve").status_code, 404)

    def test_unknown_alert_is_a_404(self):
        self._login("op")
        self.assertEqual(self._post("/api/alerts/999999/remediation/approve").status_code, 404)


if __name__ == "__main__":
    unittest.main()
