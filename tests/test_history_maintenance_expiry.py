"""A maintenance window that expires mid-poll must be reflected in that
same poll's result, not one cycle late."""
import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory

from pinoc.database import Database
from pinoc.history import HistoryManager


class MaintenanceExpiryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(self.tmp.name + "/pinoc.db")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(
            self.db, {"core_interval_seconds": 60, "network_interval_seconds": 60,
                      "storage_interval_seconds": 60, "thresholds": {"cpu_duration_seconds": 0}})

    def device(self, stamp):
        return {"id": "pi", "hostname": "pi", "friendly_name": "Pi", "online": True,
                "last_seen": stamp, "boot_time": "2026-01-01T00:00:00+00:00",
                "uptime_seconds": 100, "cpu": {"utilization_percent": 10, "temperature_c": 40},
                "memory": {"percent": 10}, "hardware": {},
                "network": {"interface": "eth0", "ip": "10.0.0.1", "rx_bytes": 1, "tx_bytes": 2},
                "storage": [], "services": []}

    def test_expired_maintenance_is_cleared_in_the_same_cycle(self):
        now = datetime.now(timezone.utc)
        expired_until = (now - timedelta(seconds=5)).isoformat()
        self.db.execute(
            "INSERT INTO device_operational_state VALUES(?,?,?,?,?,?,?,?)",
            ("pi", expired_until, "scheduled window", 1, "maintenance", expired_until,
             now.isoformat(), "admin"))
        d = self.device(now.isoformat())
        self.history._device(d, now.isoformat())
        self.assertFalse(d["maintenance"])
        self.assertIsNone(d["maintenance_until"])
        row = self.db.rows("SELECT * FROM device_operational_state WHERE device_id='pi'")[0]
        self.assertIsNone(row["maintenance_until"])


if __name__ == "__main__":
    unittest.main()
