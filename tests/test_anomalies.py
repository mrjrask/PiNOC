"""Coverage for statistical anomaly detection (pinoc/anomalies.py).

Three layers are exercised:

* :class:`BaselineTrackerTest` -- EWMA baseline math, z-score evaluation,
  outlier rejection, seasonality, staleness, and the preview ring, against a
  real database;
* :class:`HistoryManagerAnomalyTest` -- detection plugged into the history
  writer's alert reconcile: open, hysteresis, and resolve through the durable
  alert engine;
* :class:`ConfigValidationTest` / :class:`WebTest` -- configuration validation
  and the ``GET /api/anomalies`` surface.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.anomalies import METRICS, BaselineTracker
from pinoc.config_store import validate_anomaly_detection
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc
BASE = datetime(2026, 9, 21, 14, 0, tzinfo=UTC)


def _stamp(hours=0, minutes=0):
    return (BASE + timedelta(hours=hours, minutes=minutes)).isoformat()


def _device(memory=40.0, **overrides):
    """A sample with only the memory metric populated; everything else is
    absent so the tracker has exactly one signal to judge."""
    d = {"id": "pi", "online": True,
         "cpu": {"utilization_percent": None, "load_1m": None, "temperature_c": None},
         "memory": {"percent": memory},
         "network": {"rx_rate": None, "tx_rate": None}}
    d.update(overrides)
    return d


class BaselineTrackerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.tracker = BaselineTracker(self.db, {
            "enabled": True, "alerting": True, "min_samples": 10,
            "z_open": 3.0, "z_hysteresis": 2.0, "ewma_alpha": 0.3,
            "outlier_limit": 8.0, "hourly_seasonality": False,
        })

    def _baseline(self, metric="memory_percent", hour=-1):
        rows = self.db.rows("SELECT * FROM metric_baselines WHERE device_id='pi' "
                            "AND metric=? AND hour=?", (metric, hour))
        return rows[0] if rows else None

    def test_observe_issues_one_baseline_query_for_all_metrics(self):
        # observe() previously issued one SELECT per tracked metric (6 by
        # default). It should fetch every metric's baseline rows for the
        # device in a single query instead of fanning out one per metric.
        full_device = {"id": "pi", "online": True,
                       "cpu": {"utilization_percent": 10.0, "load_1m": 1.0, "temperature_c": 40.0},
                       "memory": {"percent": 40.0},
                       "network": {"rx_rate": 100.0, "tx_rate": 100.0}}
        queries = []
        real_rows = self.db.rows
        def counting_rows(sql, params=()):
            if "metric_baselines" in sql and "SELECT" in sql:
                queries.append(sql)
            return real_rows(sql, params)
        self.db.rows = counting_rows
        try:
            self.tracker.observe(full_device, _stamp())
        finally:
            self.db.rows = real_rows
        self.assertEqual(len(queries), 1)

    def test_disabled_tracker_is_inert(self):
        tracker = BaselineTracker(self.db)
        self.assertEqual(tracker.observe(_device(99.0), _stamp()), [])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM metric_baselines"), 0)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM anomaly_previews"), 0)

    def test_learns_then_flags_large_deviation(self):
        for i in range(10):
            self.assertEqual(self.tracker.observe(_device(40.0 + 0.1 * i), _stamp(minutes=i)), [])
        row = self._baseline()
        self.assertEqual(row["samples"], 10)
        self.assertAlmostEqual(row["ewma_mean"], 40.45, delta=0.5)
        result = self.tracker.observe(_device(55.0), _stamp(minutes=10))
        self.assertEqual(len(result), 1)
        anomaly = result[0]
        self.assertEqual(anomaly["metric"], "memory_percent")
        self.assertGreater(anomaly["z"], 3.0)
        self.assertEqual(anomaly["severity"], "warning")
        self.assertIn("Memory utilization", anomaly["message"])
        # A value back near the baseline is not re-flagged.
        self.assertEqual(self.tracker.observe(_device(40.5), _stamp(minutes=6)), [])

    def test_outlier_does_not_distort_baseline(self):
        for i in range(5):
            self.tracker.observe(_device(40.0), _stamp(minutes=i))
        # A 10x spike is recorded for recency but must not move the mean.
        self.tracker.observe(_device(400.0), _stamp(minutes=5))
        row = self._baseline()
        self.assertAlmostEqual(row["ewma_mean"], 40.0, delta=0.5)
        self.assertLess(row["ewma_var"], 1.0)

    def test_min_samples_gate(self):
        for i in range(9):
            self.tracker.observe(_device(40.0), _stamp(minutes=i))
        # The 10th sample deviates 5σ — well above z_open, but the baseline
        # has only 9 samples, so it is learned without being judged.
        self.assertEqual(self.tracker.observe(_device(42.0), _stamp(minutes=9)), [])
        # Now mature: the same distance is flagged.
        result = self.tracker.observe(_device(50.0), _stamp(minutes=10))
        self.assertEqual(len(result), 1)

    def test_hourly_seasonality(self):
        tracker = BaselineTracker(self.db, {
            "enabled": True, "alerting": True, "min_samples": 10,
            "z_open": 3.0, "z_hysteresis": 2.0, "ewma_alpha": 0.3,
            "hourly_seasonality": True,
        })
        # A two-level daily pattern: 40 at 14:00, 60 at 15:00.  The 14:00
        # regime matches the global baseline; the 15:00 regime bootstraps its
        # own bucket (its samples are absorbed by the bucket even while they
        # still look extreme against the global).
        for i in range(10):
            self.assertEqual(tracker.observe(_device(40.0), _stamp(minutes=i)), [])
            tracker.observe(_device(60.0), _stamp(hours=1, minutes=i))
        rows = {row["hour"]: row for row in self.db.rows(
            "SELECT * FROM metric_baselines WHERE device_id='pi' AND metric='memory_percent'")}
        self.assertEqual(set(rows), {-1, 14, 15})
        self.assertAlmostEqual(rows[14]["ewma_mean"], 40.0, delta=0.5)
        self.assertAlmostEqual(rows[15]["ewma_mean"], 60.0, delta=0.5)
        # Now that the 15:00 bucket is mature, 60 at 15:00 is normal despite
        # being 20 above the 14:00 bucket.
        self.assertEqual(tracker.observe(_device(60.0), _stamp(hours=1, minutes=10)), [])
        # The same value at 14:00 is far outside that hour's baseline.
        result = tracker.observe(_device(60.0), _stamp(minutes=10))
        self.assertEqual(len(result), 1)

    def test_stale_baseline_relearns_without_judging(self):
        tracker = BaselineTracker(self.db, {
            "enabled": True, "alerting": True, "min_samples": 10,
            "z_open": 3.0, "z_hysteresis": 2.0, "ewma_alpha": 0.3,
            "max_baseline_age_seconds": 86400, "hourly_seasonality": False,
        })
        for i in range(10):
            tracker.observe(_device(40.0), _stamp(minutes=i))
        # Thirty hours of silence exceed the 24h max age, so the first sample
        # after the gap re-learns instead of judging against stale baselines.
        result = tracker.observe(_device(90.0), _stamp(hours=30))
        self.assertEqual(result, [])
        row = self._baseline()
        self.assertGreater(row["ewma_mean"], 40.0)  # re-learning began
        self.assertEqual(row["samples"], 11)

    def test_preview_mode_records_bounded_ring(self):
        tracker = BaselineTracker(self.db, {
            "enabled": True, "alerting": False, "min_samples": 10,
            "z_open": 3.0, "z_hysteresis": 2.0, "ewma_alpha": 0.3,
            "preview_keep": 3, "hourly_seasonality": False,
        })
        for i in range(10):
            self.assertEqual(tracker.observe(_device(40.0), _stamp(minutes=i)), [])
        for i in range(5):
            self.assertEqual(tracker.observe(_device(90.0), _stamp(minutes=10 + i)), [])
        self.assertEqual(tracker.previews(100), self.db.rows(
            "SELECT * FROM anomaly_previews ORDER BY timestamp DESC, id DESC"))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM anomaly_previews"), 3)  # ring bound
        newest = tracker.previews(100)[0]
        self.assertGreater(newest["z_score"], 3.0)

    def test_maintenance_and_offline_samples_are_skipped(self):
        self.tracker.observe(_device(99.0, maintenance=True), _stamp())
        self.tracker.observe(_device(99.0, online=False), _stamp())
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM metric_baselines"), 0)

    def test_per_metric_enable_flag(self):
        tracker = BaselineTracker(self.db, {
            "enabled": True, "alerting": True, "min_samples": 5, "hourly_seasonality": False,
            "metrics": {"memory_percent": {"enabled": False}},
        })
        self.assertEqual(tracker.observe(_device(99.0), _stamp()), [])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM metric_baselines WHERE metric='memory_percent'"), 0)
        self.assertEqual(sorted(METRICS), ["cpu_percent", "cpu_temp_c", "load_1m",
                                           "memory_percent", "rx_rate_bps", "tx_rate_bps"])


class HistoryManagerAnomalyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {}, anomalies={
            "enabled": True, "alerting": True, "min_samples": 10,
            "z_open": 3.0, "z_hysteresis": 2.0, "ewma_alpha": 0.3,
            "outlier_limit": 8.0, "hourly_seasonality": False,
            "metrics": {name: {"enabled": False} for name in
                        ("cpu_percent", "load_1m", "cpu_temp_c", "rx_rate_bps", "tx_rate_bps")},
        })

    def test_alert_opens_on_deviation_and_resolves_on_recovery(self):
        for i in range(10):
            self.history._alerts(_device(40.0), _stamp(minutes=i))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM alerts"), 0)
        self.history._alerts(_device(55.0), _stamp(minutes=10))
        rows = self.db.rows("SELECT * FROM alerts WHERE device_id='pi'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["alert_type"], "anomaly")
        self.assertEqual(rows[0]["fingerprint"], "pi:anomaly:memory_percent")
        self.assertEqual(rows[0]["state"], "active")
        self.assertEqual(rows[0]["severity"], "warning")
        # A mild sample stays above the hysteresis band, so the alert persists.
        self.history._alerts(_device(41.0), _stamp(minutes=11))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"), 1)
        # Back to normal: the fingerprint is not in the active set, so the
        # durable alert engine resolves it.
        self.history._alerts(_device(40.2), _stamp(minutes=12))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"), 0)
        self.assertIsNotNone(self.db.scalar("SELECT resolved_at FROM alerts WHERE alert_id=1"))
        self.assertIn("alert_resolved",
                      {row["event_type"] for row in self.db.rows("SELECT event_type FROM events")})

    def test_preview_mode_never_opens_alerts(self):
        self.history.anomaly.alerting = False
        for i in range(10):
            self.history._alerts(_device(40.0), _stamp(minutes=i))
        self.history._alerts(_device(55.0), _stamp(minutes=10))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM alerts"), 0)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM anomaly_previews"), 1)

    def test_maintenance_suppresses_learning_and_alerts(self):
        for i in range(10):
            self.history._alerts(_device(40.0, maintenance=True), _stamp(minutes=i))
        self.history._alerts(_device(55.0, maintenance=True), _stamp(minutes=10))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM alerts"), 0)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM metric_baselines"), 0)

    def test_absent_section_is_a_noop(self):
        history = HistoryManager(self.db, {})
        for i in range(6):
            history._alerts(_device(55.0), _stamp(minutes=i))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM alerts"), 0)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM metric_baselines"), 0)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM anomaly_previews"), 0)


class ConfigValidationTest(unittest.TestCase):
    def test_absent_section_is_valid(self):
        validate_anomaly_detection({})
        validate_anomaly_detection({"anomaly_detection": None})

    def test_valid_section(self):
        validate_anomaly_detection({"anomaly_detection": {
            "enabled": True, "alerting": False, "z_open": 3.5, "z_hysteresis": 2.5,
            "ewma_alpha": 0.03, "min_samples": 50, "preview_keep": 200,
            "hourly_seasonality": True, "max_baseline_age_seconds": 86400,
            "severity": "warning",
            "metrics": {"memory_percent": {"enabled": True, "z_open": 4.0}},
        }})

    def test_invalid_values(self):
        def expect_error(section, needle):
            with self.assertRaises(ValueError) as ctx:
                validate_anomaly_detection({"anomaly_detection": section})
            self.assertIn(needle, str(ctx.exception))
        expect_error({"enabled": "yes"}, "anomaly_detection.enabled")
        expect_error({"z_open": 0}, "z_open")
        expect_error({"z_open": 200}, "z_open")
        expect_error({"ewma_alpha": 1.0}, "ewma_alpha")
        expect_error({"min_samples": 5}, "min_samples")
        expect_error({"preview_keep": 0}, "preview_keep")
        expect_error({"max_baseline_age_seconds": 10}, "max_baseline_age_seconds")
        expect_error({"severity": "loud"}, "severity")
        expect_error({"metrics": {"bogus": {}}}, "bogus")
        expect_error({"metrics": {"memory_percent": {"enabled": "yes"}}}, "enabled")
        expect_error({"metrics": {"memory_percent": {"z_open": "high"}}}, "z_open")


class _Coordinator:
    def refresh_device(self, d):
        pass

    def refresh(self):
        pass


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        from pinoc.security import SecurityManager
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {}, anomalies={
            "enabled": True, "alerting": False, "hourly_seasonality": False})
        self.state = PiNOCState()
        self.state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                                        address="host", collection_method="ssh",
                                        ssh_user="pi", ssh_port=22)], replace=True)
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True, "SECRET_KEY": "test-secret",
                         "PINOC_CONFIG": {"anomaly_detection": {"enabled": True, "alerting": False}}},
            self.history, _Coordinator())
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        for username, role in (("boss", "administrator"), ("op", "operator"), ("watch", "viewer")):
            self.security.create_user(username, "pw12345678", role)
        self.client = self.app.test_client()

    def _login(self, username):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post("/login", data={"username": username,
                                                "password": "pw12345678", "csrf_token": csrf})

    def test_endpoint_shape_and_permission(self):
        self._login("watch")  # viewer holds history.read
        response = self.client.get("/api/anomalies")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"]["mode"], "preview")
        self.assertFalse(data["status"]["alerting"])
        self.assertIn("memory_percent", data["status"]["metrics"])
        self.assertEqual(data["previews"], [])

    def test_previews_are_listed(self):
        self.db.execute(
            "INSERT INTO anomaly_previews(timestamp,device_id,metric,value,baseline_mean,baseline_std,z_score,hour) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (_stamp(), "pi", "memory_percent", 90.0, 40.0, 1.0, 50.0, 14))
        self._login("op")
        data = self.client.get("/api/anomalies?limit=5").get_json()
        self.assertEqual(len(data["previews"]), 1)
        self.assertEqual(data["previews"][0]["metric"], "memory_percent")
        self.assertEqual(data["status"]["baselines"], [])

    def test_settings_page_shows_panel(self):
        self._login("boss")
        body = self.client.get("/settings").data.decode()
        self.assertIn("anomalies-status", body)
        self.assertIn("Anomaly detection", body)


if __name__ == "__main__":
    unittest.main()
