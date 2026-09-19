"""Coverage for the history export API (/api/export/<kind>)."""
import csv
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.security import SecurityManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app


def iso(seconds_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def build(tmp_path: str, enabled: bool = False, with_history: bool = True):
    db = Database(f"{tmp_path}/db.sqlite")
    assert db.initialize()
    history = HistoryManager(db, {}) if with_history else None
    state = PiNOCState()
    state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                               collection_method="ssh")], replace=True)
    config = {"TESTING": True}
    if with_history:
        config.update({"AUTH_ENABLED": enabled, "SECRET_KEY": "test-secret", "DATABASE": db})
    return create_app(state, config, history, None), db


def seed(db: Database) -> None:
    # 30m, 2h, and 48h-old metric samples for "pi"; a 1h-old sample for "rv".
    for seconds in (1800, 7200, 172800):
        db.execute("INSERT OR IGNORE INTO device_metrics(timestamp,device_id,cpu_percent) VALUES(?,?,?)",
                   (iso(seconds), "pi", round(10 + seconds / 1000, 1)))
    db.execute("INSERT OR IGNORE INTO device_metrics(timestamp,device_id,cpu_percent) VALUES(?,?,?)",
               (iso(3600), "rv", 55.0))
    db.execute("INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,metadata_json) "
               "VALUES(?,?,?,?,?,?,?,?,?)",
               ("pi", "high_memory", "warning", "Memory utilization is 90.0%",
                "pi:high_memory:", iso(3600), iso(1800), "active", "{}"))
    db.execute("INSERT INTO events(timestamp,device_id,event_type,severity,message,metadata_json) VALUES(?,?,?,?,?,?)",
               (iso(600), "pi", "device_online", "info", "Device returned online", "{}"))
    db.execute("INSERT INTO events(timestamp,device_id,event_type,severity,message,metadata_json) VALUES(?,?,?,?,?,?)",
               (iso(400000), None, "pinoc_started", "info", "PiNOC started", "{}"))


class ExportApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name)
        seed(self.db)
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def test_json_and_csv_output(self):
        payload = self.client.get("/api/export/metrics?format=json&range=24h").get_json()
        # The 48h sample is outside 24h; the other three rows are inside.
        self.assertEqual(payload["count"], 3)
        self.assertEqual([x["device_id"] for x in payload["rows"]], ["pi", "pi", "rv"])

        csv_response = self.client.get("/api/export/metrics?format=csv&range=24h")
        self.assertEqual(csv_response.status_code, 200)
        self.assertTrue(csv_response.content_type.startswith("text/csv"))
        self.assertIn("attachment", csv_response.headers["Content-Disposition"])
        self.assertIn("pinoc-metrics-24h.csv", csv_response.headers["Content-Disposition"])
        lines = csv_response.get_data(as_text=True).splitlines()
        self.assertIn("timestamp", lines[0].split(","))
        self.assertIn("device_id", lines[0].split(","))
        self.assertEqual(len(lines), 4)  # header + 3 rows

    def test_range_device_and_limit_filters(self):
        self.assertEqual(self.client.get("/api/export/metrics?format=json&range=1h").get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/export/metrics?format=json&range=6h").get_json()["count"], 3)  # 30m + 2h pi rows + 1h rv row
        self.assertEqual(self.client.get("/api/export/metrics?format=json&range=30d").get_json()["count"], 4)
        payload = self.client.get("/api/export/metrics?format=json&range=30d&device=rv").get_json()
        self.assertEqual([x["device_id"] for x in payload["rows"]], ["rv"])
        self.assertEqual(self.client.get("/api/export/metrics?format=json&limit=1").get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/export/metrics?format=json&limit=0").get_json()["count"], 1)

    def test_alerts_and_events_exports(self):
        alerts = self.client.get("/api/export/alerts?format=json&range=30d").get_json()
        self.assertEqual(alerts["count"], 1)
        self.assertEqual(alerts["rows"][0]["alert_type"], "high_memory")
        events = self.client.get("/api/export/events?format=json&range=30d").get_json()
        self.assertEqual(events["count"], 2)  # includes the NULL-device system event
        self.assertIsNone(events["rows"][1]["device_id"])
        self.assertEqual(events["rows"][0]["event_type"], "device_online")  # newest first
        self.assertEqual(
            self.client.get("/api/export/events?format=json").get_json()["count"], 1)  # 24h default

    def test_invalid_inputs(self):
        self.assertEqual(self.client.get("/api/export/bogus").status_code, 400)
        self.assertEqual(self.client.get("/api/export/metrics?range=2w").status_code, 400)
        self.assertEqual(self.client.get("/api/export/metrics?format=xml").status_code, 400)
        self.assertEqual(self.client.get("/api/export/metrics?limit=abc").status_code, 400)

    def test_csv_neutralizes_formula_prefixed_text(self):
        hostile = ['=HYPERLINK("https://evil.example")', "+cmd|calc", "-cmd|'A!A'", "@SUM(A1)"]
        for message in hostile:
            self.db.execute("INSERT INTO events(timestamp,device_id,event_type,severity,message,metadata_json) VALUES(?,?,?,?,?,?)",
                            (iso(120), "pi", "device_online", "info", message, "{}"))
        text = self.client.get("/api/export/events?format=csv&range=24h").get_data(as_text=True)
        rows = list(csv.reader(io.StringIO(text)))
        messages = [row[rows[0].index("message")] for row in rows[1:]]
        # Every formula-prefixed text cell is apostrophe-prefixed so a
        # spreadsheet viewer stores it as text; ordinary text is untouched.
        self.assertEqual(set(messages), {"'" + m for m in hostile} | {"Device returned online"})
        # JSON exports return the raw values (formula evaluation is a
        # spreadsheet-only concern).
        payload = self.client.get("/api/export/events?format=json&range=24h").get_json()
        self.assertIn('=HYPERLINK("https://evil.example")', [r["message"] for r in payload["rows"]])

    def test_csv_keeps_numeric_cells_unmodified(self):
        self.db.execute("INSERT INTO device_metrics(timestamp,device_id,cpu_percent) VALUES(?,?,?)",
                        (iso(120), "pi", -5.5))
        text = self.client.get("/api/export/metrics?format=csv&range=1h").get_data(as_text=True)
        rows = list(csv.reader(io.StringIO(text)))
        cpu = [row[rows[0].index("cpu_percent")] for row in rows[1:]]
        # Negative numbers keep their natural representation: no apostrophe.
        self.assertIn("-5.5", cpu)
        self.assertNotIn([cell for cell in cpu if cell.startswith("'")], cpu)

    def test_unauthenticated_token_gets_401(self):
        with tempfile.TemporaryDirectory() as folder:
            enabled_app, db = build(folder, enabled=True)
            seed(db)
            try:
                client = enabled_app.test_client()
                self.assertEqual(client.get("/api/export/metrics").status_code, 401)
                self.assertEqual(client.get("/api/export/alerts").status_code, 401)
            finally:
                actions = enabled_app.extensions.get("pinoc_actions")
                if actions:
                    actions.stop()


class ExportGatingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name, enabled=True)
        seed(self.db)
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        self.security.create_user("person", "correct horse battery", "administrator")
        self.security.create_user("watcher", "correct horse battery", "viewer")
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def test_token_scopes_gate_per_kind(self):
        history_token = self.security.create_token("person", ["read:history"])
        alerts_token = self.security.create_token("person", ["read:alerts"])
        fleet_token = self.security.create_token("person", ["read:fleet"])
        self.assertEqual(self.client.get("/api/export/metrics", headers={"Authorization": "Bearer " + history_token}).status_code, 200)
        self.assertEqual(self.client.get("/api/export/alerts", headers={"Authorization": "Bearer " + history_token}).status_code, 403)
        self.assertEqual(self.client.get("/api/export/alerts", headers={"Authorization": "Bearer " + alerts_token}).status_code, 200)
        self.assertEqual(self.client.get("/api/export/metrics", headers={"Authorization": "Bearer " + alerts_token}).status_code, 403)
        self.assertEqual(self.client.get("/api/export/events", headers={"Authorization": "Bearer " + alerts_token}).status_code, 403)
        self.assertEqual(self.client.get("/api/export/metrics", headers={"Authorization": "Bearer " + fleet_token}).status_code, 403)

    def test_viewer_session_can_export(self):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        self.assertEqual(
            self.client.post("/login", data={"username": "watcher", "password": "correct horse battery",
                                              "csrf_token": csrf}).status_code, 302)
        self.assertEqual(self.client.get("/api/export/metrics?format=json").status_code, 200)
        self.assertEqual(self.client.get("/api/export/alerts?format=json").status_code, 200)


class ExportAvailabilityTest(unittest.TestCase):
    def test_503_without_history(self):
        self._tmp = tempfile.TemporaryDirectory()
        try:
            app, _ = build(self._tmp.name, with_history=False)
            self.assertEqual(app.test_client().get("/api/export/metrics").status_code, 503)
        finally:
            self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
