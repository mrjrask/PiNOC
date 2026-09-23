"""Coverage for console self-monitoring (pinoc/self_monitoring.py).

Three layers:

* :class:`SignalTest` -- the pure per-signal computations (collector
  success rate, cache staleness, database health, scheduler lag, agent
  reachability, queue depth) against fake/injected inputs, no service, no
  database, no scheduler;
* :class:`SchedulerInstrumentationTest` -- the bookkeeping added to
  pinoc.collectors.scheduler.CollectionScheduler (stats_snapshot,
  heartbeat_snapshot, task_intervals) against a real running scheduler;
* :class:`ServiceTest` -- SelfMonitoringService.tick() opening/resolving
  console_self_* alerts through the real alerts table (a real Database,
  fake scheduler/db-backed agents+jobs), proving threshold behavior and
  the open/resolve lifecycle end to end;
* :class:`WebTest` -- the /console-status page and /api/console-status
  endpoint through create_app + Flask's test client.
"""
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.collectors.scheduler import CollectionScheduler, CollectionTask
from pinoc.database import Database, utcnow
from pinoc.self_monitoring import (
    ALERT_PREFIX, CONSOLE_DEVICE_ID, SelfMonitoringService,
    agent_reachability, cache_staleness, collector_health, database_health,
    queue_depth, scheduler_lag,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


def iso(seconds_ago: float = 0) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()


class SignalTest(unittest.TestCase):
    def test_collector_health_success_rate_and_failing_flag(self):
        stats = {
            "fleet": {"total_runs": 10, "success_count": 9, "error_count": 1,
                      "consecutive_errors": 0, "last_error": None},
            "probes": {"total_runs": 5, "success_count": 1, "error_count": 4,
                       "consecutive_errors": 4, "last_error": "timeout"},
        }
        out = collector_health(stats, {"consecutive_failure_threshold": 3})
        self.assertAlmostEqual(out["fleet"]["success_rate"], 0.9)
        self.assertFalse(out["fleet"]["failing"])
        self.assertAlmostEqual(out["probes"]["success_rate"], 0.2)
        self.assertTrue(out["probes"]["failing"])

    def test_collector_health_no_runs_yet(self):
        out = collector_health({"local": {"total_runs": 0, "success_count": 0, "error_count": 0}})
        self.assertIsNone(out["local"]["success_rate"])
        self.assertFalse(out["local"]["failing"])

    def test_cache_staleness_flags_domain_older_than_multiplier(self):
        now = datetime.now(UTC)
        stats = {
            "fleet": {"last_success_at": (now - timedelta(seconds=5)).isoformat()},
            "storage": {"last_success_at": (now - timedelta(seconds=1000)).isoformat()},
        }
        intervals = {"fleet": 10.0, "storage": 60.0}
        out = cache_staleness(stats, intervals, now, {"cache_stale_multiplier": 3.0, "cache_stale_minimum_seconds": 30})
        self.assertFalse(out["fleet"]["stale"])
        self.assertTrue(out["storage"]["stale"])

    def test_cache_staleness_never_succeeded(self):
        out = cache_staleness({"fleet": {"last_success_at": None}}, {"fleet": 10.0})
        self.assertIsNone(out["fleet"]["age_seconds"])
        self.assertFalse(out["fleet"]["stale"])

    def test_database_health_size_ceiling_and_retention_lag(self):
        now = datetime.now(UTC)
        status = {"status": "ok", "size_bytes": 3 * 1024 * 1024 * 1024,
                  "last_retention_cleanup": (now - timedelta(hours=5)).isoformat()}
        out = database_health(status, {"events": 100}, now,
                              {"database_size_ceiling_bytes": 2 * 1024 ** 3, "database_retention_stale_seconds": 7200})
        self.assertTrue(out["over_size_ceiling"])
        self.assertTrue(out["retention_lagging"])
        self.assertEqual(out["row_counts"]["events"], 100)

    def test_database_health_under_ceiling_and_fresh_retention(self):
        now = datetime.now(UTC)
        status = {"status": "ok", "size_bytes": 1024, "last_retention_cleanup": now.isoformat()}
        out = database_health(status, {}, now, {"database_size_ceiling_bytes": 2 * 1024 ** 3})
        self.assertFalse(out["over_size_ceiling"])
        self.assertFalse(out["retention_lagging"])

    def test_scheduler_lag_flags_stalled_heartbeat_and_task_lag(self):
        snapshot = {"heartbeat_age_seconds": 45.0, "tasks": {"fleet": {"last_lag_seconds": 2.0, "max_lag_seconds": 3.0}}}
        out = scheduler_lag(snapshot, config={"scheduler_heartbeat_stale_seconds": 30.0, "scheduler_lag_seconds": 30.0})
        self.assertTrue(out["heartbeat_stalled"])
        self.assertTrue(out["lagging"])

        healthy = scheduler_lag({"heartbeat_age_seconds": 0.1, "tasks": {"fleet": {"last_lag_seconds": 0.0, "max_lag_seconds": 0.5}}},
                                config={"scheduler_heartbeat_stale_seconds": 30.0, "scheduler_lag_seconds": 30.0})
        self.assertFalse(healthy["lagging"])

    def test_agent_reachability_offline_past_expected_interval(self):
        rows = [
            {"agent_id": "a1", "device_id": "pi-a", "hostname": "pi-a", "enabled": 1,
             "status": "online", "last_seen": iso(30)},
            {"agent_id": "a2", "device_id": "pi-b", "hostname": "pi-b", "enabled": 1,
             "status": "online", "last_seen": iso(9000)},
            {"agent_id": "a3", "device_id": "pi-c", "hostname": "pi-c", "enabled": 0,
             "status": "disabled", "last_seen": iso(9000)},
        ]
        out = {row["agent_id"]: row for row in agent_reachability(rows, config={"agent_offline_seconds": 600})}
        self.assertFalse(out["a1"]["offline"])
        self.assertTrue(out["a2"]["offline"])
        self.assertFalse(out["a3"]["offline"])  # disabled agents are not flagged offline

    def test_agent_reachability_never_seen_is_offline(self):
        out = agent_reachability([{"agent_id": "a1", "enabled": 1, "last_seen": None}])
        self.assertTrue(out[0]["offline"])

    def test_queue_depth_backlog_by_count_and_by_age(self):
        by_count = queue_depth(
            [{"status": "queued", "requested_at": iso(1)} for _ in range(25)],
            config={"queue_backlog_depth": 20, "queue_backlog_age_seconds": 900})
        self.assertTrue(by_count["backlogged"])
        self.assertEqual(by_count["depth"], 25)

        by_age = queue_depth([{"status": "queued", "requested_at": iso(2000)}],
                             config={"queue_backlog_depth": 20, "queue_backlog_age_seconds": 900})
        self.assertTrue(by_age["backlogged"])
        self.assertAlmostEqual(by_age["oldest_queued_age_seconds"], 2000, delta=5)

        fine = queue_depth([{"status": "queued", "requested_at": iso(1)}],
                           config={"queue_backlog_depth": 20, "queue_backlog_age_seconds": 900})
        self.assertFalse(fine["backlogged"])


class SchedulerInstrumentationTest(unittest.TestCase):
    def test_stats_snapshot_tracks_success_and_consecutive_errors(self):
        calls = {"n": 0}
        gate = threading.Event()

        def flaky():
            calls["n"] += 1
            if calls["n"] <= 2:
                raise RuntimeError("boom")
            gate.set()

        scheduler = CollectionScheduler([CollectionTask("flaky", 1, flaky)])
        scheduler.start()
        try:
            self.assertTrue(gate.wait(5))
            deadline = time.monotonic() + 2
            stats = {}
            while time.monotonic() < deadline:
                stats = scheduler.stats_snapshot()["flaky"]
                if stats["success_count"] >= 1:
                    break
                time.sleep(0.01)
            self.assertGreaterEqual(stats["total_runs"], 3)
            self.assertEqual(stats["success_count"], 1)
            self.assertEqual(stats["consecutive_errors"], 0)
            self.assertIsNotNone(stats["last_success_at"])
        finally:
            scheduler.stop()

    def test_heartbeat_snapshot_and_task_intervals(self):
        scheduler = CollectionScheduler([CollectionTask("fast", 5, lambda: None)])
        scheduler.start()
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not scheduler.stats_snapshot()["fast"]["total_runs"]:
                time.sleep(0.01)
            heartbeat = scheduler.heartbeat_snapshot()
            self.assertIsNotNone(heartbeat["heartbeat_age_seconds"])
            self.assertIn("fast", heartbeat["tasks"])
            self.assertEqual(scheduler.task_intervals(), {"fast": 5.0})
        finally:
            scheduler.stop()

    def test_persistently_failing_task_does_not_block_scheduler_thread(self):
        # Same isolation guarantee test_collector_scheduler.py checks for the
        # un-instrumented scheduler; the added bookkeeping must not change it.
        other = threading.Event()
        scheduler = CollectionScheduler([
            CollectionTask("always_fails", 60, lambda: (_ for _ in ()).throw(RuntimeError("x"))),
            CollectionTask("healthy", 60, other.set),
        ])
        scheduler.start()
        try:
            self.assertTrue(other.wait(2))
        finally:
            scheduler.stop()


class FakeScheduler:
    """Stands in for CollectionScheduler for SelfMonitoringService tests."""

    def __init__(self, stats=None, intervals=None, heartbeat=None):
        self._stats = stats or {}
        self._intervals = intervals or {}
        self._heartbeat = heartbeat or {"heartbeat_age_seconds": 0.1, "tasks": {}}

    def stats_snapshot(self):
        return self._stats

    def task_intervals(self):
        return self._intervals

    def heartbeat_snapshot(self):
        return self._heartbeat


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()

    def _open_alerts(self):
        return self.db.rows("SELECT * FROM alerts WHERE device_id=? AND resolved_at IS NULL", (CONSOLE_DEVICE_ID,))

    def test_failing_collector_opens_alert_and_recovery_resolves_it(self):
        stats = {"fleet": {"total_runs": 6, "success_count": 0, "error_count": 6,
                           "consecutive_errors": 6, "last_error": "ssh timeout",
                           "last_success_at": None}}
        service = SelfMonitoringService(self.db, state=self.state, scheduler=FakeScheduler(stats=stats),
                                        config={"consecutive_failure_threshold": 3}, interval=9999)
        service.tick()
        open_alerts = self._open_alerts()
        self.assertEqual(len(open_alerts), 1)
        self.assertEqual(open_alerts[0]["alert_type"], f"{ALERT_PREFIX}collector_failing")
        self.assertEqual(open_alerts[0]["severity"], "critical")

        # Recovery: the task now succeeds -- the alert must resolve, and the
        # shared state cache must reflect zero open alerts.
        stats["fleet"] = {"total_runs": 6, "success_count": 1, "error_count": 5,
                          "consecutive_errors": 0, "last_error": None, "last_success_at": utcnow()}
        service.tick()
        self.assertEqual(self._open_alerts(), [])
        self.assertEqual(self.state.alerts(), [])

    def test_database_size_ceiling_opens_alert(self):
        # A real Database's status() reports the real file size, so exercise
        # the threshold with a tiny configured ceiling rather than writing
        # gigabytes of fixture data.
        service = SelfMonitoringService(self.db, state=self.state, scheduler=FakeScheduler(),
                                        config={"database_size_ceiling_bytes": 1}, interval=9999)
        service.tick()
        rows = self._open_alerts()
        types = {row["alert_type"] for row in rows}
        self.assertIn(f"{ALERT_PREFIX}database_size", types)

    def test_database_retention_lag_opens_alert(self):
        self.db.last_retention_cleanup = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        service = SelfMonitoringService(self.db, state=self.state, scheduler=FakeScheduler(),
                                        config={"database_size_ceiling_bytes": 10**12,
                                                "database_retention_stale_seconds": 3600}, interval=9999)
        service.tick()
        types = {row["alert_type"] for row in self._open_alerts()}
        self.assertIn(f"{ALERT_PREFIX}database_retention_lag", types)

    def test_scheduler_lag_opens_alert(self):
        heartbeat = {"heartbeat_age_seconds": 120.0, "tasks": {}}
        service = SelfMonitoringService(self.db, state=self.state,
                                        scheduler=FakeScheduler(heartbeat=heartbeat),
                                        config={"database_size_ceiling_bytes": 10**12,
                                                "scheduler_heartbeat_stale_seconds": 30}, interval=9999)
        service.tick()
        types = {row["alert_type"] for row in self._open_alerts()}
        self.assertIn(f"{ALERT_PREFIX}scheduler_lag", types)

    def test_agent_offline_opens_alert(self):
        self.db.execute(
            "INSERT INTO agents(agent_id,device_id,credential_hash,agent_version,protocol_version,status,"
            "enabled,created_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
            ("agent-1", "pi-a", "hash", "1.0", 1, "online", 1, utcnow(), iso(9000)))
        service = SelfMonitoringService(self.db, state=self.state, scheduler=FakeScheduler(),
                                        config={"database_size_ceiling_bytes": 10**12,
                                                "agent_offline_seconds": 600}, interval=9999)
        service.tick()
        rows = self._open_alerts()
        types = {row["alert_type"] for row in rows}
        self.assertIn(f"{ALERT_PREFIX}agent_offline", types)

    def test_action_queue_backlog_opens_alert(self):
        for i in range(25):
            self.db.execute(
                "INSERT INTO action_jobs(job_id,device_id,action,requested_by,requested_role,requested_at,status) "
                "VALUES(?,?,?,?,?,?,?)",
                (f"job-{i}", "pi-a", "service.restart", "tester", "operator", utcnow(), "queued"))
        service = SelfMonitoringService(self.db, state=self.state, scheduler=FakeScheduler(),
                                        config={"database_size_ceiling_bytes": 10**12,
                                                "queue_backlog_depth": 20}, interval=9999)
        service.tick()
        types = {row["alert_type"] for row in self._open_alerts()}
        self.assertIn(f"{ALERT_PREFIX}action_queue_backlog", types)

    def test_no_signals_crossed_opens_nothing(self):
        stats = {"fleet": {"total_runs": 5, "success_count": 5, "error_count": 0,
                           "consecutive_errors": 0, "last_error": None, "last_success_at": utcnow()}}
        service = SelfMonitoringService(self.db, state=self.state,
                                        scheduler=FakeScheduler(stats=stats, intervals={"fleet": 10.0}),
                                        config={"database_size_ceiling_bytes": 10**12}, interval=9999)
        service.tick()
        self.assertEqual(self._open_alerts(), [])

    def test_snapshot_works_without_db_or_scheduler(self):
        service = SelfMonitoringService(db=None, state=None, scheduler=None)
        report = service.snapshot()
        self.assertEqual(report["collectors"], {})
        self.assertEqual(report["database"]["status"], "disabled")
        service.start()  # must not start a thread (no db to persist alerts against)
        self.assertFalse(service.thread.is_alive())


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        from pinoc.history import HistoryManager
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        stats = {"fleet": {"total_runs": 4, "success_count": 4, "error_count": 0,
                           "consecutive_errors": 0, "last_error": None, "last_success_at": utcnow()}}
        self.service = SelfMonitoringService(self.db, state=self.state,
                                             scheduler=FakeScheduler(stats=stats, intervals={"fleet": 10.0}),
                                             interval=9999)
        config = {"TESTING": True, "DATABASE": self.db}
        self.app = create_app(self.state, config, self.history, None, self_monitoring=self.service)
        self.client = self.app.test_client()

    def test_console_status_page_renders(self):
        resp = self.client.get("/console-status")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Console status", resp.data)

    def test_api_console_status_returns_snapshot(self):
        resp = self.client.get("/api/console-status")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        for key in ("collectors", "cache", "database", "scheduler", "agents", "queue"):
            self.assertIn(key, body)
        self.assertIn("fleet", body["collectors"])

    def test_api_console_status_without_service_is_unavailable(self):
        app = create_app(self.state, {"TESTING": True, "DATABASE": self.db}, self.history, None)
        client = app.test_client()
        resp = client.get("/api/console-status")
        self.assertEqual(resp.status_code, 503)

    def test_console_alert_visible_through_the_normal_alerts_api(self):
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,"
            "metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (CONSOLE_DEVICE_ID, f"{ALERT_PREFIX}collector_failing", "critical", "fleet collection is failing",
             f"{CONSOLE_DEVICE_ID}:{ALERT_PREFIX}collector_failing:fleet", utcnow(), utcnow(), "active", "{}"))
        resp = self.client.get("/api/alerts")
        self.assertEqual(resp.status_code, 200)
        alerts = resp.get_json()["alerts"]
        self.assertTrue(any(a["device_id"] == CONSOLE_DEVICE_ID for a in alerts))


if __name__ == "__main__":
    unittest.main()
