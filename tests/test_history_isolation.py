"""One device's malformed telemetry must not abort the whole snapshot cycle."""
import unittest
from datetime import datetime, timezone
from tempfile import TemporaryDirectory

from pinoc.database import Database, SCHEMA_VERSION
from pinoc.history import HistoryManager


class SnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(self.tmp.name + "/pinoc.db")
        self.assertTrue(self.db.initialize(), self.db.error)
        self.history = HistoryManager(
            self.db, {"core_interval_seconds": 60, "network_interval_seconds": 60,
                      "storage_interval_seconds": 60, "thresholds": {"cpu_duration_seconds": 0}})

    def device(self, device_id, stamp, temp=75, storage=None):
        return {"id": device_id, "hostname": device_id, "friendly_name": device_id,
                "online": True, "last_seen": stamp, "boot_time": "2026-01-01T00:00:00+00:00",
                "uptime_seconds": 100, "cpu": {"utilization_percent": 95, "temperature_c": temp},
                "memory": {"percent": 90}, "hardware": {},
                "network": {"interface": "eth0", "ip": "10.0.0.1", "rx_bytes": 1, "tx_bytes": 2},
                "storage": storage if storage is not None else
                    [{"mount_point": "/", "total": 1000, "used": 850, "available": 150, "percent": 85}],
                "services": []}

    def test_one_broken_device_does_not_abort_the_rest_of_the_snapshot(self):
        now = datetime.now(timezone.utc).isoformat()
        # A malformed storage entry (not a dict) makes _sample()/_device()
        # raise while processing this device, simulating a collector that
        # returned unexpected data for one Pi in the fleet.
        broken = self.device("broken", now, storage=["not-a-dict"])
        healthy = self.device("healthy", now)

        # The broken device is processed first so a non-isolated loop would
        # never reach the healthy one.
        self.history._snapshot([broken, healthy], now)

        device_ids = {row["device_id"] for row in self.db.rows("SELECT device_id FROM devices")}
        self.assertIn("healthy", device_ids)
        self.assertEqual(
            self.db.scalar("SELECT COUNT(*) FROM alerts WHERE device_id='healthy' AND alert_type='high_temperature'"),
            1)

    def test_healthy_devices_after_a_broken_one_are_still_cached(self):
        now = datetime.now(timezone.utc).isoformat()
        broken = self.device("broken", now, storage=["not-a-dict"])
        healthy = self.device("healthy", now)

        class FakeState:
            def __init__(self):
                self.alerts = None

            def set_alerts(self, alerts):
                self.alerts = alerts

        self.history.state = FakeState()
        self.history._snapshot([broken, healthy], now)
        # _refresh_cache() must still run for the batch despite the earlier failure.
        self.assertIsNotNone(self.history.state.alerts)
        self.assertTrue(any(a["device_id"] == "healthy" for a in self.history.state.alerts))


if __name__ == "__main__":
    unittest.main()
