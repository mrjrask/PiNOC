"""Coverage for notification channels, validation, history integration, and web routes."""
import json
import smtplib
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from pinoc.config_store import validate_config, validate_notifications
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.notifications import NotificationService
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

REPO_ROOT = Path(__file__).resolve().parent.parent


class RecordingHandler(BaseHTTPRequestHandler):
    records = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        type(self).records.append({"path": self.path,
                                    "headers": {k: v for k, v in self.headers.items()},
                                    "body": self.rfile.read(length).decode()})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class ChannelServer:
    def setUp(self):
        RecordingHandler.records = []
        self.server = HTTPServer(("127.0.0.1", 0), RecordingHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def url(self, path=""):
        return f"http://127.0.0.1:{self.port}{path}"


class ValidationTest(unittest.TestCase):
    @staticmethod
    def section(**overrides):
        value = {"enabled": True, "open_severities": ["warning", "critical"],
                 "channels": [{"id": "n1", "kind": "ntfy", "url": "https://ntfy.example", "topic": "pinoc"}]}
        value.update(overrides)
        return {"notifications": value}

    def assertInvalid(self, value, fragment):
        with self.assertRaises(ValueError) as caught:
            validate_notifications(value)
        self.assertIn(fragment, str(caught.exception))

    def test_valid_section_accepted(self):
        self.assertIsNone(validate_notifications(self.section(
            resolve_severities=["warning"],
            channels=[
                {"id": "n1", "kind": "ntfy", "url": "https://ntfy.example", "topic": "pinoc", "enabled": True},
                {"id": "s1", "kind": "smtp", "host": "mail.example", "port": 587,
                 "username": "pinoc", "password": "hunter2", "from": "pinoc@example",
                 "to": ["ops@example"], "starttls": True},
                {"id": "w1", "kind": "webhook", "url": "https://hooks.example/pinoc", "enabled": False},
            ])))

    def test_enabled_must_be_boolean(self):
        self.assertInvalid(self.section(enabled="yes"), "enabled")

    def test_severities_must_be_known(self):
        self.assertInvalid(self.section(open_severities=["fatal"]), "open_severities")

    def test_channel_kind_must_be_known(self):
        self.assertInvalid(self.section(channels=[{"id": "x", "kind": "pagerduty"}]), "kind")

    def test_channel_ids_must_be_unique(self):
        self.assertInvalid(self.section(channels=[
            {"id": "a", "kind": "webhook", "url": "https://x.example"},
            {"id": "a", "kind": "webhook", "url": "https://y.example"}]), "id")

    def test_ntfy_requires_url_and_topic(self):
        self.assertInvalid(self.section(channels=[{"id": "n", "kind": "ntfy", "topic": "pinoc"}]), "url")
        self.assertInvalid(self.section(channels=[{"id": "n", "kind": "ntfy", "url": "https://ntfy.example", "topic": "  "}]), "topic")

    def test_webhook_requires_http_url(self):
        self.assertInvalid(self.section(channels=[{"id": "w", "kind": "webhook", "url": "ftp://x.example"}]), "url")

    def test_smtp_requires_host_port_and_recipients(self):
        self.assertInvalid(self.section(channels=[{"id": "s", "kind": "smtp", "to": ["a@example"]}]), "host")
        self.assertInvalid(self.section(channels=[{"id": "s", "kind": "smtp", "host": "mail.example", "port": 0, "to": ["a@example"]}]), "port")
        self.assertInvalid(self.section(channels=[{"id": "s", "kind": "smtp", "host": "mail.example", "port": "one", "to": ["a@example"]}]), "port")
        self.assertInvalid(self.section(channels=[{"id": "s", "kind": "smtp", "host": "mail.example", "to": []}]), "to")

    def test_validate_config_includes_notifications(self):
        # The shipped config validates end to end, and an invalid notifications
        # section now fails the documented preflight check.
        shipped = json.loads((REPO_ROOT / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_config(shipped, REPO_ROOT), shipped)
        broken = json.loads(json.dumps(shipped))
        broken["notifications"]["channels"] = [{"id": "x", "kind": "pagerduty"}]
        with self.assertRaises(ValueError):
            validate_config(broken, REPO_ROOT)


class DeliveryTest(ChannelServer, unittest.TestCase):
    def test_ntfy_and_webhook_receivers(self):
        config = {"enabled": True, "open_severities": ["warning", "critical"],
                  "channels": [
                      {"id": "n1", "kind": "ntfy", "url": self.url(), "topic": "pinoc ops"},
                      {"id": "w1", "kind": "webhook", "url": self.url("/hook")},
                  ]}
        service = NotificationService(config)
        service.enqueue("open", {"device_id": "pi", "alert_type": "high_memory",
                                  "severity": "warning", "message": "Memory utilization is 90.0%"}, "Pi One")
        service.start()
        try:
            deadline = time.monotonic() + 5
            while len(RecordingHandler.records) < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            service.stop()
        self.assertEqual(len(RecordingHandler.records), 2)
        ntfy, webhook = RecordingHandler.records
        self.assertEqual(ntfy["path"], "/pinoc%20ops")
        # Headers are latin-1: the em dash degrades, the body keeps full UTF-8.
        self.assertEqual(ntfy["headers"].get("X-Title"), "PiNOC open: Pi One ? high_memory")
        self.assertEqual(ntfy["body"], "Pi One: Memory utilization is 90.0%")
        self.assertNotIn("X-Priority", ntfy["headers"])  # warning uses the default priority
        payload = json.loads(webhook["body"])
        self.assertEqual(payload["source"], "pinoc")
        self.assertEqual(payload["transition"], "open")
        self.assertEqual(payload["device_id"], "pi")
        self.assertEqual(payload["alert_type"], "high_memory")
        self.assertEqual(payload["severity"], "warning")
        self.assertEqual(payload["subject"], "PiNOC open: Pi One — high_memory")

    def test_critical_alert_uses_high_ntfy_priority(self):
        config = {"enabled": True, "channels": [{"id": "n1", "kind": "ntfy", "url": self.url(), "topic": "pinoc"}]}
        service = NotificationService(config)
        service.enqueue("open", {"device_id": "pi", "alert_type": "device_offline",
                                  "severity": "critical", "message": "Device is offline"}, "Pi One")
        service.start()
        try:
            deadline = time.monotonic() + 5
            while not RecordingHandler.records and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            service.stop()
        self.assertEqual(RecordingHandler.records[0]["headers"].get("X-Priority"), "high")


class SmtpSendTest(unittest.TestCase):
    def send(self, channel):
        service = NotificationService({"enabled": True}, sender=None, timeout=7.5)
        message = service._message("open", {"device_id": "pi", "alert_type": "high_memory",
                                             "severity": "warning", "message": "Memory 90%"}, "Pi One")
        with mock.patch("pinoc.notifications.smtplib.SMTP") as smtp_class:
            instance = smtp_class.return_value.__enter__.return_value
            ok, error = service._send(channel, message)
        return service, ok, error, smtp_class, instance

    def test_authenticated_starttls_delivery(self):
        channel = {"id": "s1", "kind": "smtp", "host": "mail.example", "port": 587,
                   "username": "pinoc", "password": "hunter2", "from": "pinoc@example",
                   "to": ["ops@example", "cto@example"], "starttls": True}
        _, ok, error, smtp_class, instance = self.send(channel)
        self.assertTrue(ok)
        self.assertIsNone(error)
        smtp_class.assert_called_once_with("mail.example", 587, timeout=7.5)
        instance.starttls.assert_called_once()
        instance.login.assert_called_once_with("pinoc", "hunter2")
        email = instance.send_message.call_args[0][0]
        self.assertEqual(email["Subject"], "PiNOC open: Pi One — high_memory")
        self.assertEqual(email["To"], "ops@example, cto@example")
        self.assertEqual(email["From"], "pinoc@example")

    def test_send_failure_reports_error(self):
        channel = {"id": "s1", "kind": "smtp", "host": "mail.example", "port": 25, "to": ["ops@example"]}
        service = NotificationService({"enabled": True}, timeout=7.5)
        message = service._message("open", {"device_id": "pi", "alert_type": "high_memory",
                                             "severity": "warning", "message": "Memory 90%"}, "Pi One")
        with mock.patch("pinoc.notifications.smtplib.SMTP") as smtp_class:
            instance = smtp_class.return_value.__enter__.return_value
            instance.send_message.side_effect = smtplib.SMTPException("mailbox rejected")
            ok, error = service._send(channel, message)
        instance.starttls.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("mailbox rejected", error)

    def test_unknown_kind_reports_error(self):
        service = NotificationService({"enabled": True})
        message = service._message("open", {"device_id": "pi", "alert_type": "x",
                                             "severity": "info", "message": "x"}, "Pi")
        ok, error = service._send({"id": "x", "kind": "carrier-pigeon"}, message)
        self.assertFalse(ok)
        self.assertIn("carrier-pigeon", error)


class SeverityFilterTest(unittest.TestCase):
    def setUp(self):
        self.service = NotificationService({"enabled": True, "open_severities": ["critical"],
                                             "resolve_severities": ["critical"]})

    def open(self, severity):
        self.service.enqueue("open", {"device_id": "pi", "alert_type": "x",
                                       "severity": severity, "message": "x"}, "Pi")

    def test_filters_by_severity(self):
        self.open("warning")
        self.assertEqual(self.service.queue.qsize(), 0)
        self.open("critical")
        self.assertEqual(self.service.queue.qsize(), 1)
        self.service.enqueue("resolve", {"device_id": "pi", "alert_type": "x",
                                          "severity": "warning", "message": "x"}, "Pi")
        self.assertEqual(self.service.queue.qsize(), 1)
        self.service.enqueue("resolve", {"device_id": "pi", "alert_type": "x",
                                          "severity": "critical", "message": "x"}, "Pi")
        self.assertEqual(self.service.queue.qsize(), 2)

    def test_empty_filters_notify_everything(self):
        service = NotificationService({"enabled": True})
        service.enqueue("open", {"device_id": "pi", "alert_type": "x", "severity": "info", "message": "x"}, "Pi")
        service.enqueue("resolve", {"device_id": "pi", "alert_type": "x", "severity": "info", "message": "x"}, "Pi")
        self.assertEqual(service.queue.qsize(), 2)

    def test_disabled_service_queues_nothing_and_starts_no_worker(self):
        service = NotificationService({"enabled": False, "channels": [{"id": "n", "kind": "ntfy",
                                                                        "url": "https://x", "topic": "t"}]})
        service.enqueue("open", {"device_id": "pi", "alert_type": "x", "severity": "critical", "message": "x"}, "Pi")
        service.start()
        self.assertEqual(service.queue.qsize(), 0)
        self.assertFalse(service.thread.is_alive())
        service.stop()

    def test_status_tracks_channel_outcomes(self):
        service = NotificationService({"enabled": True, "channels": [{"id": "n", "kind": "ntfy",
                                                                       "url": "https://x", "topic": "t"}]},
                                       sender=lambda kind, channel, message: (False, "boom"))
        service.enqueue("open", {"device_id": "pi", "alert_type": "x",
                                  "severity": "critical", "message": "x"}, "Pi")
        service.start()
        try:
            deadline = time.monotonic() + 5
            while service.status()["channels"][0]["failed"] < 1 and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            service.stop()
        channel = service.status()["channels"][0]
        self.assertEqual(channel["failed"], 1)
        self.assertEqual(channel["sent"], 0)
        self.assertEqual(channel["last_error"], "boom")
        self.assertEqual(len(channel["recent"]), 1)
        self.assertFalse(channel["recent"][0]["ok"])


class HistoryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.recorder = []
        self.history = HistoryManager(self.db, {}, None, notifier=Recorder(self.recorder))

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def device(temperature=45.0, cpu=10.0, memory=30.0, **extra):
        base = {"id": "pi", "hostname": "pi", "friendly_name": "Pi", "online": True, "maintenance": False,
                "cpu": {"utilization_percent": cpu, "temperature_c": temperature},
                "memory": {"percent": memory}, "storage": [], "media": [], "services": [],
                "integrations": {}, "hardware": {}, "uptime_seconds": 3600}
        base.update(extra)
        return base

    def stamp(self, offset_seconds):
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()

    def test_alert_open_and_resolve_are_notified(self):
        self.history._device(self.device(), self.stamp(0))
        self.assertEqual(self.recorder, [])  # healthy: no transitions
        self.history._device(self.device(temperature=85.0, cpu=99.5, memory=90.0), self.stamp(10))
        opens = [(t, alert["alert_type"]) for t, alert, _ in self.recorder if t == "open"]
        self.assertEqual(set(opens), {("open", "critical_temperature"), ("open", "high_memory")})
        self.assertEqual({name for _, _, name in self.recorder}, {"Pi"})
        self.history._device(self.device(), self.stamp(20))
        resolves = [(t, alert["alert_type"]) for t, alert, _ in self.recorder if t == "resolve"]
        self.assertEqual(set(resolves), {("resolve", "critical_temperature"), ("resolve", "high_memory")})
        self.assertEqual(self.db.rows("SELECT COUNT(*) AS n FROM alerts WHERE resolved_at IS NULL"), [{"n": 0}])

    def test_maintenance_suppresses_notifications(self):
        self.history._device(self.device(temperature=85.0, maintenance=True), self.stamp(0))
        self.assertEqual(self.recorder, [])
        self.history._device(self.device(), self.stamp(10))
        self.assertEqual(self.recorder, [])  # recovered under/after maintenance: no churn

    def test_without_notifier_nothing_is_notified(self):
        self.history.notifier = None
        self.history._device(self.device(temperature=85.0), self.stamp(0))
        self.history._device(self.device(), self.stamp(10))
        self.assertEqual(self.recorder, [])


class Recorder:
    def __init__(self, sink):
        self.sink = sink

    def enqueue(self, transition, alert, device_name):
        self.sink.append((transition, dict(alert), device_name))


def build(tmp_path, enabled=False, notifications=None, with_history=True):
    db = Database(f"{tmp_path}/db.sqlite")
    assert db.initialize()
    history = HistoryManager(db, {}) if with_history else None
    state = PiNOCState()
    config = {"TESTING": True}
    if with_history:
        config.update({"AUTH_ENABLED": enabled, "SECRET_KEY": "test-secret", "DATABASE": db})
    return create_app(state, config, history, None, notifications), db


class ApiRouteTest(ChannelServer, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()
        super().tearDown()

    def notifications(self):
        return NotificationService({
            "enabled": True, "open_severities": ["critical"],
            "channels": [{"id": "w1", "kind": "webhook", "url": self.url("/hook")}]})

    def test_disabled_service_reports_empty(self):
        app, _ = build(self._tmp.name)
        self.app = app
        client = app.test_client()
        payload = client.get("/api/notifications").get_json()
        self.assertEqual(payload, {"enabled": False, "channels": []})
        csrf = client.get("/api/session").get_json()["csrf_token"]
        response = client.post("/api/notifications/test", json={"channel": "w1"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 409)

    def test_status_lists_channels(self):
        self.app, _ = build(self._tmp.name, notifications=self.notifications())
        payload = self.app.test_client().get("/api/notifications").get_json()
        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["channels"][0]["id"], "w1")
        self.assertEqual(payload["channels"][0]["kind"], "webhook")

    def test_test_endpoint_delivers(self):
        self.app, _ = build(self._tmp.name, notifications=self.notifications())
        client = self.app.test_client()
        csrf = client.get("/api/session").get_json()["csrf_token"]
        response = client.post("/api/notifications/test", json={"channel": "w1"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(RecordingHandler.records[0]["path"], "/hook")
        self.assertIn("Test message", json.loads(RecordingHandler.records[0]["body"])["body"])
        unknown = client.post("/api/notifications/test", json={"channel": "missing"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(unknown.status_code, 404)

    def test_token_scopes_and_roles(self):
        self.app, _ = build(self._tmp.name, enabled=True, notifications=self.notifications())
        security = self.app.extensions["pinoc_security"]
        security.create_user("boss", "correct horse battery", "administrator")
        security.create_user("watcher", "correct horse battery", "viewer")
        client = self.app.test_client()
        admin = security.create_token("boss", ["admin:config"])
        fleet = security.create_token("boss", ["read:fleet"])
        self.assertEqual(client.get("/api/notifications").status_code, 401)  # unauthenticated API call
        self.assertEqual(client.get("/api/notifications", headers={"Authorization": f"Bearer {fleet}"}).status_code, 403)
        self.assertEqual(client.get("/api/notifications", headers={"Authorization": f"Bearer {admin}"}).status_code, 200)
        # Role floor: a viewer session cannot manage notifications.
        security.create_user("plain", "correct horse battery", "viewer")
        client.get("/login")
        with client.session_transaction() as session:
            csrf = session["csrf_token"]
        client.post("/login", data={"username": "plain", "password": "correct horse battery", "csrf_token": csrf})
        self.assertEqual(client.get("/api/notifications").status_code, 403)


if __name__ == "__main__":
    unittest.main()
