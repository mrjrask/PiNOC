"""Coverage for staged fleet software maintenance (pinoc/rollout.py).

Two layers, matching tests/test_remediation.py's split:

* :class:`PlanTest` -- the pure wave-planning helper, no DB or service
  involved;
* :class:`EngineTest` -- the service's bookkeeping (wave sequencing, health
  gate pass/fail, halt-on-failure, kernel-change reboot logic, maintenance
  gating, result-table/summary persistence) against a real database with a
  fake ActionDispatcher, so job/reboot outcomes are fully deterministic and
  each tick advances exactly one step;
* :class:`RealDispatcherTest` -- one end-to-end run against a genuine
  ``ActionDispatcher`` (stubbed subprocess runner) proving a rollout
  enqueues apt.upgrade/device.reboot through the *real* action queue and
  audit trail, not a parallel mechanism.
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
from pinoc.rollout import RolloutService, plan_waves
from pinoc.state import PiNOCState

UTC = timezone.utc


def make_device(device_id="pi-a", **overrides) -> DeviceState:
    values = dict(id=device_id, hostname=device_id, friendly_name=device_id, online=True,
                  health="healthy", address="host", collection_method="ssh", ssh_user="pi",
                  ssh_port=22, roles=["general"], tags=[], allowed_actions=["apt.upgrade"],
                  kernel="6.1.0-1-arm64", applications={"packages": {"updates_available": 5}})
    values.update(overrides)
    return DeviceState(**values)


class PlanTest(unittest.TestCase):
    def test_canary_count_then_one_remainder_wave(self):
        waves = plan_waves(["b", "a", "d", "c"], canary_count=1)
        self.assertEqual(waves, [["a"], ["b", "c", "d"]])

    def test_explicit_canary_devices_take_priority_over_count(self):
        waves = plan_waves(["a", "b", "c"], canary_device_ids=["c"], canary_count=1)
        self.assertEqual(waves, [["c"], ["a", "b"]])

    def test_wave_size_chunks_the_remainder(self):
        waves = plan_waves(["a", "b", "c", "d", "e"], canary_count=1, wave_size=2)
        self.assertEqual(waves, [["a"], ["b", "c"], ["d", "e"]])

    def test_no_canary_still_produces_one_wave(self):
        self.assertEqual(plan_waves(["b", "a"]), [["a", "b"]])

    def test_empty_selection_is_no_waves(self):
        self.assertEqual(plan_waves([]), [])


class _FakeActions:
    """Stands in for ActionDispatcher: enqueue()/get() operate on a real
    action_jobs table (so RolloutService's own reconciliation queries work
    unmodified) without anything running asynchronously -- a test drives a
    job to a terminal state explicitly, one tick at a time. ``fail`` makes
    the next N enqueue() calls raise (a dispatch failure)."""

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

    def get(self, job_id):
        rows = self.db.rows("SELECT * FROM action_jobs WHERE job_id=?", (job_id,))
        return rows[0] if rows else None

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
        self.actions = _FakeActions(self.db)
        self.svc = RolloutService(self.db, self.actions, state=self.state, interval=9999)

    def _publish(self, *devices):
        self.state.publish(list(devices), replace=True)

    def _complete(self, job_id, status="succeeded", reboot_required=False, error=None):
        summary = f"apt upgrade completed (reboot_required={1 if reboot_required else 0})"
        self.db.execute("UPDATE action_jobs SET status=?,summary=?,error=? WHERE job_id=?",
                        (status, summary, error, job_id))

    def _complete_reboot(self, job_id, status="succeeded"):
        self.db.execute("UPDATE action_jobs SET status=?,summary='rebooted' WHERE job_id=?",
                        (status, job_id))

    def _device_row(self, run_id, device_id):
        rows = [r for r in self.svc.devices(run_id) if r["device_id"] == device_id]
        return rows[0]

    def _run_device_to_success(self, run_id, device_id, reboot_required=False):
        """Drive one device row from 'pending' to 'succeeded' via ticks,
        matching exactly the steps RolloutService itself performs."""
        self.svc.tick()  # pending -> updating (enqueues apt.upgrade)
        row = self._device_row(run_id, device_id)
        self._complete(row["update_job_id"], reboot_required=reboot_required)
        self.svc.tick()  # updating -> rebooting (if required) or verifying
        if reboot_required:
            row = self._device_row(run_id, device_id)
            self._complete_reboot(row["reboot_job_id"])
            self.svc.tick()  # rebooting -> verifying
        self.svc.tick()  # verifying -> succeeded (device is online + healthy)

    # -- wave sequencing -----------------------------------------------------
    def test_canary_wave_runs_before_remainder(self):
        self._publish(make_device("a"), make_device("b"), make_device("c"), make_device("d"))
        run = self.svc.create_run(scope="all", roles=["general"], canary_count=2,
                                  respect_maintenance=False, requested_by="alice")
        self.assertEqual(run["wave_count"], 2)
        rows = {r["device_id"]: r for r in self.svc.devices(run["run_id"])}
        self.assertEqual(rows["a"]["wave"], 0)
        self.assertEqual(rows["b"]["wave"], 0)
        self.assertEqual(rows["c"]["wave"], 1)
        self.assertEqual(rows["c"]["status"], "not_started")
        self.svc.tick()  # only dispatches wave 0
        enqueued_devices = {j["device_id"] for j in self.actions.enqueued}
        self.assertEqual(enqueued_devices, {"a", "b"})
        # Remainder must still be untouched until wave 0 fully succeeds.
        self.assertEqual(self._device_row(run["run_id"], "c")["status"], "not_started")

    def test_remainder_starts_only_after_canary_wave_succeeds(self):
        self._publish(make_device("a"), make_device("b"))
        run = self.svc.create_run(scope="all", roles=["general"], canary_count=1,
                                  respect_maintenance=False, requested_by="alice")
        run_id = run["run_id"]
        self._run_device_to_success(run_id, "a")
        run_row = self.svc.get(run_id)
        self.assertEqual(run_row["current_wave"], 1)
        self.assertEqual(run_row["status"], "running")
        self.assertEqual(self._device_row(run_id, "b")["status"], "pending")
        self.svc.tick()  # now wave 1 dispatches
        self.assertIn("b", {j["device_id"] for j in self.actions.enqueued})

    # -- health gate -----------------------------------------------------
    def test_health_gate_pass_marks_device_and_run_succeeded(self):
        self._publish(make_device("a", kernel="6.1.0-1"))
        run = self.svc.create_run(scope="all", roles=["general"], respect_maintenance=False,
                                  requested_by="alice")
        run_id = run["run_id"]
        self._run_device_to_success(run_id, "a")
        row = self._device_row(run_id, "a")
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(row["before_kernel"], "6.1.0-1")
        self.assertEqual(row["after_kernel"], "6.1.0-1")
        self.assertEqual(self.svc.get(run_id)["status"], "completed")

    def test_health_gate_failure_halts_the_rollout(self):
        self._publish(make_device("a"), make_device("b"))
        run = self.svc.create_run(scope="all", roles=["general"], canary_count=1,
                                  respect_maintenance=False, requested_by="alice")
        run_id = run["run_id"]
        self.svc.tick()  # a: pending -> updating
        row = self._device_row(run_id, "a")
        self._complete(row["update_job_id"])
        self.svc.tick()  # a: updating -> verifying
        # The update "worked" but left the device unhealthy.
        self._publish(make_device("a", health="critical"), make_device("b"))
        self.svc.tick()  # a: verifying -> failed, run halts
        self.assertEqual(self._device_row(run_id, "a")["status"], "failed")
        run_row = self.svc.get(run_id)
        self.assertEqual(run_row["status"], "halted")
        self.assertIn("critical health", run_row["halted_reason"])
        # Wave 1 ("b") must never have been touched.
        self.assertEqual(self._device_row(run_id, "b")["status"], "skipped")
        self.assertEqual({j["device_id"] for j in self.actions.enqueued}, {"a"})

    def test_halt_notifies(self):
        calls = []

        class _Notifier:
            enabled = True

            def enqueue(self, transition, payload):
                calls.append((transition, payload))

        self._publish(make_device("a", health="critical"))
        svc = RolloutService(self.db, self.actions, state=self.state, notifier=_Notifier(), interval=9999)
        run = svc.create_run(scope="all", roles=["general"], respect_maintenance=False, requested_by="alice")
        run_id = run["run_id"]
        svc.tick()  # pending -> updating
        row = self._device_row(run_id, "a")
        self._complete(row["update_job_id"])
        svc.tick()  # updating -> verifying
        svc.tick()  # verifying (device already critical) -> failed -> halt
        self.assertEqual(svc.get(run_id)["status"], "halted")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "open")
        self.assertEqual(calls[0][1]["alert_type"], "rollout_halted")

    # -- kernel-change / reboot logic -----------------------------------
    def test_reboot_required_triggers_device_reboot_before_verifying(self):
        self._publish(make_device("a", kernel="6.1.0-1"))
        run = self.svc.create_run(scope="all", roles=["general"], respect_maintenance=False,
                                  requested_by="alice")
        run_id = run["run_id"]
        self.svc.tick()  # pending -> updating
        row = self._device_row(run_id, "a")
        self._complete(row["update_job_id"], reboot_required=True)
        self.svc.tick()  # updating -> rebooting (device.reboot enqueued)
        row = self._device_row(run_id, "a")
        self.assertEqual(row["status"], "rebooting")
        self.assertIsNotNone(row["reboot_job_id"])
        self.assertIn("device.reboot", {j["action"] for j in self.actions.enqueued})
        self._complete_reboot(row["reboot_job_id"])
        self.svc.tick()  # rebooting -> verifying
        self.assertEqual(self._device_row(run_id, "a")["status"], "verifying")
        # Simulate the device having come back up on the new kernel.
        self._publish(make_device("a", kernel="6.1.0-2"))
        self.svc.tick()  # verifying -> succeeded, with the new kernel recorded
        row = self._device_row(run_id, "a")
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(row["before_kernel"], "6.1.0-1")
        self.assertEqual(row["after_kernel"], "6.1.0-2")
        self.assertEqual(row["reboot_required"], 1)

    def test_no_reboot_required_skips_reboot_and_goes_straight_to_verifying(self):
        self._publish(make_device("a"))
        run = self.svc.create_run(scope="all", roles=["general"], respect_maintenance=False,
                                  requested_by="alice")
        run_id = run["run_id"]
        self.svc.tick()
        row = self._device_row(run_id, "a")
        self._complete(row["update_job_id"], reboot_required=False)
        self.svc.tick()
        row = self._device_row(run_id, "a")
        self.assertEqual(row["status"], "verifying")
        self.assertIsNone(row["reboot_job_id"])
        self.assertNotIn("device.reboot", {j["action"] for j in self.actions.enqueued})

    def test_device_that_never_comes_back_online_fails_the_gate(self):
        self._publish(make_device("a", online=False))
        run = self.svc.create_run(scope="all", roles=["general"], respect_maintenance=False,
                                  requested_by="alice")
        # The device is offline, so create_run's own online check doesn't
        # apply (that's ActionDispatcher.validate()'s job at dispatch time);
        # force it straight into 'verifying' with a reboot pending and an
        # already-expired wait window to exercise the timeout path.
        run_id = run["run_id"]
        self.db.execute(
            "UPDATE rollout_devices SET status='verifying',reboot_required=1,reboot_at=? WHERE run_id=?",
            ((datetime.now(UTC) - timedelta(seconds=1000)).isoformat(), run_id))
        self.svc.tick()
        row = self._device_row(run_id, "a")
        self.assertEqual(row["status"], "failed")
        self.assertIn("did not come back online", row["error"])

    # -- maintenance-window gating ---------------------------------------
    def test_dispatch_waits_for_the_devices_own_maintenance_window(self):
        self._publish(make_device("a", maintenance=False))
        run = self.svc.create_run(scope="all", roles=["general"], respect_maintenance=True,
                                  requested_by="alice")
        run_id = run["run_id"]
        self.svc.tick()
        self.assertEqual(self.actions.enqueued, [])
        self.assertEqual(self._device_row(run_id, "a")["status"], "pending")
        self._publish(make_device("a", maintenance=True))
        self.svc.tick()
        self.assertEqual(len(self.actions.enqueued), 1)
        self.assertEqual(self._device_row(run_id, "a")["status"], "updating")

    def test_respect_maintenance_false_dispatches_immediately(self):
        self._publish(make_device("a", maintenance=False))
        run = self.svc.create_run(scope="all", roles=["general"], respect_maintenance=False,
                                  requested_by="alice")
        self.svc.tick()
        self.assertEqual(len(self.actions.enqueued), 1)

    # -- result table / summary persistence -------------------------------
    def test_result_table_and_summary_reflect_a_full_run(self):
        self._publish(make_device("a"), make_device("b"))
        run = self.svc.create_run(scope="security", roles=["general"], canary_count=1,
                                  respect_maintenance=False, requested_by="alice")
        run_id = run["run_id"]
        self._run_device_to_success(run_id, "a")
        self.svc.tick()  # dispatch wave 1 ("b")
        self._run_device_to_success(run_id, "b")
        rows = self.svc.devices(run_id)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["status"] == "succeeded" for r in rows))
        self.assertTrue(all(r["before_updates_available"] == 5 for r in rows))
        summary = self.svc.summary(run_id)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_status"], {"succeeded": 2})
        self.assertEqual(self.svc.get(run_id)["status"], "completed")

    # -- creation validation -------------------------------------------------
    def test_create_run_requires_an_explicit_device_selection(self):
        self._publish(make_device("a"))
        with self.assertRaises(ValueError):
            self.svc.create_run(scope="all", requested_by="alice")

    def test_create_run_rejects_an_unknown_scope(self):
        self._publish(make_device("a"))
        with self.assertRaises(ValueError):
            self.svc.create_run(scope="bogus", roles=["general"], requested_by="alice")

    def test_create_run_rejects_devices_missing_the_allowed_action(self):
        self._publish(make_device("a", allowed_actions=[]))
        with self.assertRaises(ValueError):
            self.svc.create_run(scope="all", roles=["general"], requested_by="alice")

    def test_cancel_halts_a_running_rollout(self):
        self._publish(make_device("a"), make_device("b"))
        run = self.svc.create_run(scope="all", roles=["general"], canary_count=1,
                                  respect_maintenance=False, requested_by="alice")
        run_id = run["run_id"]
        row = self.svc.cancel(run_id, requested_by="alice")
        self.assertEqual(row["status"], "halted")
        self.assertIn("cancelled by alice", row["halted_reason"])
        self.assertEqual(self._device_row(run_id, "b")["status"], "skipped")
        # A cancelled rollout must not dispatch anything on a later tick.
        self.svc.tick()
        self.assertEqual(self.actions.enqueued, [])


class RealDispatcherTest(unittest.TestCase):
    """One end-to-end pass through the genuine ActionDispatcher, including
    a real reboot triggered by the (stubbed) reboot-required check."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([make_device("a")], replace=True)
        # Every remote command (apt upgrade, the reboot-required check, and
        # the reboot itself) succeeds, so the reboot-required probe's exit
        # code is 0 -- i.e. "reboot required" -- exercising the reboot leg
        # of the flow along with the plain apt.upgrade dispatch.
        self.dispatcher = ActionDispatcher(self.db, self.state, max_workers=1,
                                           runner=lambda args, **kw: subprocess.CompletedProcess(args, 0, "", ""))
        self.addCleanup(self.dispatcher.stop)

    def test_rollout_runs_end_to_end_through_the_real_action_queue(self):
        svc = RolloutService(self.db, self.dispatcher, state=self.state, interval=9999)
        run = svc.create_run(scope="all", roles=["general"], respect_maintenance=False,
                             requested_by="alice")
        run_id = run["run_id"]

        def wait_for(predicate, timeout=5):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                svc.tick()
                if predicate():
                    return True
                time.sleep(0.05)
            return predicate()

        self.assertTrue(wait_for(lambda: svc.get(run_id)["status"] in ("completed", "halted")))
        run_row = svc.get(run_id)
        self.assertEqual(run_row["status"], "completed")
        device_row = svc.devices(run_id)[0]
        self.assertEqual(device_row["status"], "succeeded")
        self.assertEqual(device_row["reboot_required"], 1)
        self.assertIsNotNone(device_row["reboot_job_id"])
        # Both the update and the reboot went through the real dispatcher's
        # job/audit trail, indistinguishable from a manual action except for
        # who requested it.
        audited_actions = {r["action"] for r in self.db.rows(
            "SELECT action FROM audit_records WHERE device_id='a'")}
        self.assertIn("apt.upgrade", audited_actions)
        self.assertIn("device.reboot", audited_actions)
        jobs = {r["action"]: r["status"] for r in self.db.rows(
            "SELECT action,status FROM action_jobs WHERE device_id='a'")}
        self.assertEqual(jobs["apt.upgrade"], "succeeded")
        self.assertEqual(jobs["device.reboot"], "succeeded")


if __name__ == "__main__":
    unittest.main()
