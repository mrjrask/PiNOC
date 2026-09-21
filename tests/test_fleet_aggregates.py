"""Coverage for the fleet-aggregates dashboard rollup (/api/overview aggregates)."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.web.app import create_app, fleet_aggregates

UTC = timezone.utc


def live_devices():
    return [
        {"id": "pi", "hostname": "pi", "friendly_name": "Pi", "online": True,
         "cpu": {"utilization_percent": 10.0, "temperature_c": 40.0},
         "memory": {"percent": 20.0},
         "storage": [{"total": 1_000_000_000, "used": 500_000_000, "percent": 50.0, "mount_point": "/data"}],
         "network": {"rx_rate": 1_000_000, "tx_rate": 500_000},
         "uptime_seconds": 100_000},
        {"id": "rv", "hostname": "rv", "friendly_name": "Rv", "online": True,
         "cpu": {"utilization_percent": 30.0, "temperature_c": 60.0},
         "memory": {"percent": 40.0},
         "storage": [{"total": 2_000_000_000, "used": 1_000_000_000, "percent": 50.0, "mount_point": "/data"}],
         "network": {"rx_rate": 2_000_000, "tx_rate": 1_000_000},
         "uptime_seconds": 200_000},
        # Offline: must be excluded from every aggregate even with plausible values.
        {"id": "off", "hostname": "off", "friendly_name": "Off", "online": False,
         "cpu": {"utilization_percent": 99.0, "temperature_c": 85.0},
         "memory": {"percent": 90.0},
         "storage": [{"total": 8_000_000_000, "used": 7_900_000_000, "percent": 99.0, "mount_point": "/"}],
         "network": {"rx_rate": 9_000_000, "tx_rate": 9_000_000},
         "uptime_seconds": 1_000_000},
    ]


def build(tmp_path: str, enabled: bool = False, with_history: bool = True, devices=None):
    db = Database(f"{tmp_path}/db.sqlite")
    assert db.initialize()
    history = HistoryManager(db, {}) if with_history else None
    state = PiNOCState()
    state.publish([DeviceState(**d) for d in (devices if devices is not None else live_devices())], replace=True)
    config = {"TESTING": True}
    if with_history:
        config.update({"AUTH_ENABLED": enabled, "SECRET_KEY": "test-secret", "DATABASE": db})
    return create_app(state, config, history, None), db


def seed_history(db: Database, now: datetime) -> None:
    """24 hours of raw samples plus 40 hourly storage rows per device.

    "pi" storage grows 500 GiB -> 890 GiB over ~39h (unambiguous growth);
    "rv" storage is flat (stable). All rows fall inside the last-24h sparkline
    window and the 30-day forecast window.
    """
    hour = now.replace(minute=0, second=0, microsecond=0)
    for h in range(24):
        bucket = (hour - timedelta(hours=h)).strftime("%Y-%m-%dT%H:00:00+00:00")
        db.execute("INSERT OR IGNORE INTO device_metrics(timestamp,device_id,cpu_percent,cpu_temp_c,memory_percent) VALUES(?,?,?,?,?)",
                   (bucket, "pi", 10.0, 40.0, 20.0))
        db.execute("INSERT OR IGNORE INTO device_metrics(timestamp,device_id,cpu_percent,cpu_temp_c,memory_percent) VALUES(?,?,?,?,?)",
                   (bucket, "rv", 30.0, 60.0, 40.0))
        db.execute("INSERT OR IGNORE INTO network_metrics(timestamp,device_id,interface,rx_rate_bps,tx_rate_bps) VALUES(?,?,?,?,?)",
                   (bucket, "pi", "eth0", 1_000_000, 500_000))
        db.execute("INSERT OR IGNORE INTO network_metrics(timestamp,device_id,interface,rx_rate_bps,tx_rate_bps) VALUES(?,?,?,?,?)",
                   (bucket, "rv", "eth0", 2_000_000, 1_000_000))
    for i in range(40):
        timestamp = (hour - timedelta(hours=39 - i)).isoformat()
        db.execute("INSERT OR IGNORE INTO storage_metrics(timestamp,device_id,mount_point,total_bytes,used_bytes) VALUES(?,?,?,?,?)",
                   (timestamp, "pi", "/data", 1_000_000_000, 500_000_000 + i * 10_000_000))
        db.execute("INSERT OR IGNORE INTO storage_metrics(timestamp,device_id,mount_point,total_bytes,used_bytes) VALUES(?,?,?,?,?)",
                   (timestamp, "rv", "/data", 500_000_000, 100_000_000))


class AggregatesUnitTest(unittest.TestCase):
    def test_live_rollup_averages_and_sums_online_devices(self):
        result = fleet_aggregates(live_devices())
        self.assertEqual(result["online_devices"], 2)
        self.assertEqual(result["cpu_average_percent"], 20.0)  # (10 + 30) / 2
        self.assertEqual(result["cpu_max_temperature_c"], 60.0)
        self.assertEqual(result["memory_average_percent"], 30.0)
        self.assertEqual(result["storage_total_bytes"], 3_000_000_000)
        self.assertEqual(result["storage_used_bytes"], 1_500_000_000)
        self.assertEqual(result["storage_average_percent"], 50.0)
        self.assertEqual(result["rx_rate_bps"], 3_000_000)
        self.assertEqual(result["tx_rate_bps"], 1_500_000)
        self.assertEqual(result["uptime_min_seconds"], 100_000)
        self.assertEqual(result["uptime_max_seconds"], 200_000)

    def test_offline_devices_are_excluded(self):
        offline = [d for d in live_devices() if not d["online"]]
        self.assertTrue(offline)
        result = fleet_aggregates(offline)
        self.assertEqual(result["online_devices"], 0)
        self.assertIsNone(result["cpu_average_percent"])
        self.assertIsNone(result["cpu_max_temperature_c"])
        self.assertIsNone(result["memory_average_percent"])
        self.assertIsNone(result["storage_total_bytes"])
        self.assertIsNone(result["storage_used_bytes"])
        self.assertIsNone(result["storage_average_percent"])
        self.assertIsNone(result["rx_rate_bps"])
        self.assertIsNone(result["tx_rate_bps"])
        self.assertIsNone(result["uptime_min_seconds"])
        self.assertIsNone(result["uptime_max_seconds"])

    def test_without_history_history_fields_are_none(self):
        result = fleet_aggregates(live_devices())  # history=None
        self.assertIsNone(result["storage_forecast"])
        self.assertIsNone(result["sparkline"])

    def test_unavailable_history_store_is_treated_as_absent(self):
        class Unavailable:
            db = Database(":memory: unavailable")  # available=False, never initialized

        result = fleet_aggregates(live_devices(), Unavailable())
        self.assertIsNone(result["storage_forecast"])
        self.assertIsNone(result["sparkline"])
        self.assertEqual(result["online_devices"], 2)


class SparklineForecastTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)  # never started; no threads
        self.now = datetime.now(UTC)
        seed_history(self.db, self.now)

    def tearDown(self):
        self._tmp.cleanup()

    def test_sparkline_covers_last_24_hours_and_averages_devices(self):
        result = fleet_aggregates(live_devices(), self.history)
        sparkline = result["sparkline"]
        self.assertEqual(len(sparkline), 24)
        latest = sparkline[-1]
        self.assertEqual(latest["avg_cpu"], 20.0)  # (10 + 30) / 2 per bucket
        self.assertEqual(latest["avg_temp"], 50.0)
        self.assertEqual(latest["avg_memory"], 30.0)
        self.assertEqual(latest["rx_rate_bps"], 1_500_000)  # sample-weighted fleet average
        self.assertEqual(latest["tx_rate_bps"], 750_000)
        self.assertEqual(latest["storage_percent"], 66.0)  # latest raw samples: 990 MB of 1.5 GB
        self.assertIsInstance(latest["timestamp"], str)
        timestamps = [x["timestamp"] for x in sparkline]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_storage_forecast_fetches_all_top_mounts_in_one_query(self):
        # The storage-forecast fan-out previously issued one query per
        # top-used mount (up to 12) instead of a single batched query.
        queries = []
        real_rows = self.db.rows
        def counting_rows(sql, params=()):
            if "storage_metrics" in sql and "ROW_NUMBER" not in sql:
                queries.append(sql)
            return real_rows(sql, params)
        self.db.rows = counting_rows
        try:
            result = fleet_aggregates(live_devices(), self.history)
        finally:
            self.db.rows = real_rows
        self.assertEqual(result["storage_forecast"]["status"], "growing")
        self.assertEqual(len(queries), 1)

    def test_storage_forecast_uses_shortest_growing_mount(self):
        result = fleet_aggregates(live_devices(), self.history)
        forecast = result["storage_forecast"]
        self.assertEqual(forecast["status"], "growing")  # pi grows; rv is flat/stable
        self.assertIsNotNone(forecast["estimated_days_remaining"])
        self.assertGreater(forecast["estimated_days_remaining"], 0)
        self.assertLess(forecast["estimated_days_remaining"], 30)


class OverviewRouteTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def test_overview_includes_live_aggregates(self):
        self.app, _ = build(self._tmp.name)
        payload = self.app.test_client().get("/api/overview").get_json()
        self.assertEqual(payload["aggregates"]["online_devices"], 2)
        self.assertEqual(payload["aggregates"]["cpu_average_percent"], 20.0)
        # An initialized-but-empty history store reports insufficient data.
        self.assertEqual(payload["aggregates"]["storage_forecast"], {"status": "insufficient", "estimated_days_remaining": None})
        self.assertEqual(payload["aggregates"]["sparkline"], [])

    def test_overview_includes_seeded_history_aggregates(self):
        self.app, self.db = build(self._tmp.name)
        seed_history(self.db, datetime.now(UTC))
        payload = self.app.test_client().get("/api/overview").get_json()
        self.assertEqual(len(payload["aggregates"]["sparkline"]), 24)
        self.assertEqual(payload["aggregates"]["storage_forecast"]["status"], "growing")


class OverviewGatingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name, enabled=True)
        seed_history(self.db, datetime.now(UTC))
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("person", "correct horse battery", "administrator")
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def get(self, token):
        return self.client.get("/api/overview", headers={"Authorization": f"Bearer {token}"})

    def test_unauthenticated_browser_request_redirects(self):
        # /api/* answers 401 (not the browser 302) when authentication is on.
        self.assertEqual(self.client.get("/api/overview").status_code, 401)

    def test_fleet_token_gets_live_values_but_no_history(self):
        response = self.get(self.security.create_token("person", ["read:fleet"]))
        self.assertEqual(response.status_code, 200)
        aggregates = response.get_json()["aggregates"]
        self.assertEqual(aggregates["online_devices"], 2)  # live rollup still available
        self.assertEqual(aggregates["cpu_average_percent"], 20.0)
        self.assertIsNone(aggregates["storage_forecast"])
        self.assertIsNone(aggregates["sparkline"])

    def test_history_token_adds_forecast_and_sparkline(self):
        response = self.get(self.security.create_token("person", ["read:fleet", "read:history"]))
        self.assertEqual(response.status_code, 200)
        aggregates = response.get_json()["aggregates"]
        self.assertEqual(len(aggregates["sparkline"]), 24)
        self.assertEqual(aggregates["storage_forecast"]["status"], "growing")

    def test_token_without_fleet_read_cannot_read_overview(self):
        response = self.get(self.security.create_token("person", ["read:history"]))
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
