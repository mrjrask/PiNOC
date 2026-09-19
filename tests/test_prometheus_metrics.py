"""Coverage for the Prometheus /metrics endpoint."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.web.app import create_app, escape_label, render_prometheus


def iso(seconds_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def make_state() -> PiNOCState:
    state = PiNOCState()
    state.publish([
        DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True, health="healthy",
                    cpu={"utilization_percent": 12.5, "temperature_c": 45.0},
                    memory={"percent": 33.3},
                    storage=[{"device": "/dev/mmcblk0p2", "mount_point": "/", "path": "/", "percent": 51.2}],
                    services=[{"name": "ssh", "state": "running"}, {"name": "adsb", "state": "failed"}],
                    media=[{"device": "mmcblk0", "mount_points": ["/"], "media_errors": True, "io_errors": 3}],
                    uptime_seconds=1234, last_successful_collection=iso(30)),
        DeviceState(id='we"ird\\name', hostname="x", friendly_name="X", online=False, health="offline"),
    ], replace=True)
    return state


def build(tmp_path: str, enabled: bool = False, with_history: bool = True, state: PiNOCState = None):
    db = Database(f"{tmp_path}/db.sqlite")
    assert db.initialize()
    history = HistoryManager(db, {}) if with_history else None
    config = {"TESTING": True}
    if with_history:
        config.update({"AUTH_ENABLED": enabled, "SECRET_KEY": "test-secret", "DATABASE": db})
    return create_app(state or make_state(), config, history, None), db


class EndpointTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name)
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def scrape(self) -> str:
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "text/plain; version=0.0.4; charset=utf-8")
        return response.get_data(as_text=True)

    def test_renders_expected_gauges(self):
        body = self.scrape()
        self.assertIn("pinoc_fleet_devices_total 2", body)
        self.assertIn("pinoc_fleet_devices_online 1", body)
        self.assertIn('pinoc_device_up{device="pi"} 1', body)
        self.assertIn('pinoc_device_health{device="pi"} 0', body)
        self.assertIn('pinoc_device_up{device="we\\"ird\\\\name"} 0', body)
        self.assertIn('pinoc_device_health{device="we\\"ird\\\\name"} 4', body)
        self.assertIn('pinoc_device_cpu_utilization_percent{device="pi"} 12.5', body)
        self.assertIn('pinoc_device_cpu_temperature_celsius{device="pi"} 45', body)
        self.assertIn('pinoc_device_memory_percent{device="pi"} 33.3', body)
        self.assertIn('pinoc_device_disk_used_percent{device="pi",mount="/"} 51.2', body)
        self.assertIn('pinoc_device_uptime_seconds{device="pi"} 1234', body)
        self.assertIn('pinoc_device_services_failed{device="pi"} 1', body)
        self.assertIn('pinoc_device_media_errors{device="pi",medium="mmcblk0"} 1', body)
        self.assertIn("pinoc_last_collection_timestamp_seconds ", body)
        self.assertIn('pinoc_database_state{state="ok"} 1', body)
        self.assertIn('pinoc_database_state{state="disabled"} 0', body)
        self.assertIn("# HELP pinoc_device_health", body)
        self.assertIn("# TYPE pinoc_device_health gauge", body)
        # None values are omitted rather than rendered.
        self.assertNotIn('pinoc_device_cpu_temperature_celsius{device="we\\"ird\\\\name"}', body)

    def test_alert_counts(self):
        state = make_state()
        state.set_alerts([
            {"device_id": "pi", "alert_type": "high_memory", "severity": "warning", "state": "active"},
            {"device_id": "pi", "alert_type": "critical_disk_usage", "severity": "critical", "state": "acknowledged"},
            {"device_id": "pi", "alert_type": "high_memory", "severity": "warning", "state": "active"},
        ])
        app, _ = build(self._tmp.name, state=state)
        try:
            body = app.test_client().get("/metrics").get_data(as_text=True)
            self.assertIn('pinoc_alerts_total{severity="warning",state="active"} 2', body)
            self.assertIn('pinoc_alerts_total{severity="critical",state="acknowledged"} 1', body)
            # The state cache escalates device health for the highest open alert.
            self.assertIn('pinoc_device_health{device="pi"} 3', body)
        finally:
            actions = app.extensions.get("pinoc_actions")
            if actions:
                actions.stop()


class GatingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name, enabled=True)
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("person", "correct horse battery", "administrator")
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def test_token_scope_and_authentication(self):
        fleet = self.security.create_token("person", ["read:fleet"])
        history = self.security.create_token("person", ["read:history"])
        unauthenticated = self.client.get("/metrics")
        self.assertEqual(unauthenticated.status_code, 302)  # browser path redirects to login
        self.assertEqual(self.client.get("/metrics", headers={"Authorization": "Bearer " + fleet}).status_code, 200)
        self.assertEqual(self.client.get("/metrics", headers={"Authorization": "Bearer " + history}).status_code, 403)

    def test_session_viewer_can_scrape(self):
        self.security.create_user("watcher", "correct horse battery", "viewer")
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        self.assertEqual(self.client.post("/login", data={"username": "watcher", "password": "correct horse battery",
                                                          "csrf_token": csrf}).status_code, 302)
        self.assertEqual(self.client.get("/metrics").status_code, 200)


class RendererTest(unittest.TestCase):
    def test_escapes_label_values(self):
        self.assertEqual(escape_label('a"b'), 'a\\"b')
        self.assertEqual(escape_label("a\\b"), "a\\\\b")
        self.assertEqual(escape_label("a\nb"), "a\\nb")

    def test_omits_none_and_booleans(self):
        self.assertEqual(render_prometheus([("m", {}, None), ("m2", {}, True), ("m3", {"x": "1"}, 1.0)]),
                         '# HELP m3 PiNOC metric.\n# TYPE m3 gauge\nm3{x="1"} 1')

    def test_repeats_type_once(self):
        body = render_prometheus([("m", {"a": "1"}, 1), ("m", {"a": "2"}, 2)])
        self.assertEqual(body.count("# TYPE m gauge"), 1)


if __name__ == "__main__":
    unittest.main()
