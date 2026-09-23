"""Coverage for incident timelines and automatic post-mortems
(pinoc/incidents.py): synthesis triggered off cluster/alert resolution,
timeline reconstruction, MTTA/MTTR, the Incidents page/filters, and the
Markdown/JSON/printable-HTML export formats."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.incidents import (
    build_timeline, format_duration, get_incident, incident_id_for_alert,
    list_incidents, synthesize_alert, synthesize_cluster, to_html, to_json, to_markdown,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


def device(device_id, online=True, ssid="HomeWiFi", gateway="192.168.1.1", ip="192.168.1.10", **extra):
    base = {
        "id": device_id, "hostname": device_id, "friendly_name": device_id.title(),
        "online": online, "maintenance": False,
        "cpu": {"utilization_percent": 10.0, "temperature_c": 45.0},
        "memory": {"percent": 30.0}, "storage": [], "media": [], "services": [],
        "integrations": {}, "hardware": {}, "uptime_seconds": 3600,
        "network": {"ssid": ssid, "default_gateway": gateway, "ip": ip},
    }
    base.update(extra)
    return base


class SynthesisTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)

    def tearDown(self):
        self._tmp.cleanup()

    def stamp(self, offset_seconds):
        return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()

    def test_standalone_alert_resolve_synthesizes_an_incident(self):
        self.history._device(device("solo"), self.stamp(0))
        self.history._device(device("solo", online=False), self.stamp(5))
        alert_id = self.db.scalar("SELECT alert_id FROM alerts WHERE device_id='solo'")
        self.history.acknowledge(alert_id, "alice")
        self.history._device(device("solo", online=True), self.stamp(30))

        incidents = self.db.rows("SELECT * FROM incidents WHERE kind='alert'")
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(json.loads(incident["device_ids_json"]), ["solo"])
        self.assertEqual(json.loads(incident["alert_ids_json"]), [alert_id])
        self.assertIsNotNone(incident["mtta_seconds"])
        self.assertIsNotNone(incident["mttr_seconds"])
        self.assertGreaterEqual(incident["mttr_seconds"], incident["mtta_seconds"])

    def test_synthesis_is_idempotent(self):
        self.history._device(device("solo"), self.stamp(0))
        self.history._device(device("solo", online=False), self.stamp(5))
        self.history._device(device("solo", online=True), self.stamp(10))
        first_count = self.db.scalar("SELECT COUNT(*) FROM incidents")
        row = self.db.rows("SELECT * FROM alerts WHERE device_id='solo'")[0]
        # Calling synthesize_alert() again for the same already-resolved
        # alert (e.g. a defensive re-check) must not create a duplicate.
        synthesize_alert(self.db, row)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM incidents"), first_count)

    def test_clustered_alert_never_gets_its_own_standalone_incident(self):
        for name in ("a", "b"):
            self.history._device(device(name), self.stamp(0))
        self.history._device(device("a", online=False), self.stamp(10))
        self.history._device(device("b", online=False), self.stamp(11))
        self.history._device(device("a", online=True), self.stamp(20))
        self.history._device(device("b", online=True), self.stamp(21))

        cluster_incidents = self.db.rows("SELECT * FROM incidents WHERE kind='cluster'")
        alert_incidents = self.db.rows("SELECT * FROM incidents WHERE kind='alert'")
        self.assertEqual(len(cluster_incidents), 1)
        self.assertEqual(alert_incidents, [])  # a and b are covered by the cluster incident only
        self.assertEqual(sorted(json.loads(cluster_incidents[0]["device_ids_json"])), ["a", "b"])

    def test_cluster_incident_synthesizes_even_without_a_notifier(self):
        # HistoryManager here has notifier=None, so alert_clusters.
        # notified_open is never set -- incident synthesis must not depend
        # on that notification flag (see CorrelationOutcome.resolved_clusters).
        for name in ("a", "b"):
            self.history._device(device(name), self.stamp(0))
        self.history._device(device("a", online=False), self.stamp(10))
        self.history._device(device("b", online=False), self.stamp(11))
        cluster = self.db.rows("SELECT * FROM alert_clusters")[0]
        self.assertFalse(cluster["notified_open"])
        self.history._device(device("a", online=True), self.stamp(20))
        self.history._device(device("b", online=True), self.stamp(21))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM incidents WHERE kind='cluster'"), 1)

    def test_incident_id_for_alert_links_resolved_alert_to_its_incident(self):
        self.history._device(device("solo"), self.stamp(0))
        self.history._device(device("solo", online=False), self.stamp(5))
        self.history._device(device("solo", online=True), self.stamp(10))
        row = self.db.rows("SELECT * FROM alerts WHERE device_id='solo'")[0]
        incident_id = incident_id_for_alert(self.db, row)
        self.assertIsNotNone(incident_id)
        self.assertEqual(get_incident(self.db, incident_id)["alert_ids"], [row["alert_id"]])

    def test_unresolved_alert_has_no_incident_yet(self):
        self.history._device(device("solo"), self.stamp(0))
        self.history._device(device("solo", online=False), self.stamp(5))
        row = self.db.rows("SELECT * FROM alerts WHERE device_id='solo'")[0]
        self.assertIsNone(incident_id_for_alert(self.db, row))


class TimelineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)

    def tearDown(self):
        self._tmp.cleanup()

    def stamp(self, offset_seconds):
        return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()

    def test_timeline_includes_alert_action_and_notification_entries_in_order(self):
        self.history._device(device("solo"), self.stamp(-10))
        # The alert opens here (offset 0); acknowledge() below stamps with
        # its own real wall-clock time a few milliseconds later, so it is
        # guaranteed to land after this, unlike a positive synthetic offset
        # would (which can otherwise land *before* acknowledge()'s real
        # "now" and invert the expected ordering).
        self.history._device(device("solo", online=False), self.stamp(0))
        alert_id = self.db.scalar("SELECT alert_id FROM alerts WHERE device_id='solo'")
        self.history.acknowledge(alert_id, "alice")
        # A reboot action job requested and completed inside the incident
        # window, and a notification send -- both from tables the incident
        # never duplicates, only queries.
        self.db.execute(
            "INSERT INTO action_jobs(job_id,device_id,action,target,parameters_json,requested_by,requested_role,"
            "source_ip,requested_at,started_at,completed_at,status,exit_code,summary,error,duration_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("job-1", "solo", "device.reboot", None, "{}", "alice", "operator", "127.0.0.1",
             self.stamp(6), self.stamp(6), self.stamp(8), "succeeded", 0, "rebooted", None, 2000))
        self.db.execute(
            "INSERT INTO notification_log(timestamp,transition,device_id,alert_type,severity,channel_id,channel_kind,ok,error) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (self.stamp(1), "open", "solo", "device_offline", "critical", "chan", "ntfy", 1, None))
        self.history._device(device("solo", online=True), self.stamp(20))

        incident_id = self.db.scalar("SELECT incident_id FROM incidents WHERE kind='alert'")
        incident = get_incident(self.db, incident_id)
        timeline = build_timeline(self.db, incident)
        kinds = [e["kind"] for e in timeline]
        self.assertIn("alert_opened", kinds)
        self.assertIn("alert_acknowledged", kinds)
        self.assertIn("alert_resolved", kinds)
        self.assertIn("action_requested", kinds)
        self.assertIn("action_completed", kinds)
        self.assertIn("notification", kinds)
        # Chronological order.
        times = [e["time"] for e in timeline]
        self.assertEqual(times, sorted(times))
        # The alert must open before it is acknowledged, and acknowledged
        # before it resolves.
        self.assertLess(kinds.index("alert_opened"), kinds.index("alert_acknowledged"))
        self.assertLess(kinds.index("alert_acknowledged"), kinds.index("alert_resolved"))

    def test_cluster_wide_notification_appears_in_cluster_incident_timeline(self):
        for name in ("a", "b"):
            self.history._device(device(name), self.stamp(0))
        self.history._device(device("a", online=False), self.stamp(10))
        self.history._device(device("b", online=False), self.stamp(11))
        self.db.execute(
            "INSERT INTO notification_log(timestamp,transition,device_id,alert_type,severity,channel_id,channel_kind,ok,error) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (self.stamp(12), "open", None, "cluster_connectivity", "critical", "chan", "ntfy", 1, None))
        self.history._device(device("a", online=True), self.stamp(20))
        self.history._device(device("b", online=True), self.stamp(21))

        incident_id = self.db.scalar("SELECT incident_id FROM incidents WHERE kind='cluster'")
        incident = get_incident(self.db, incident_id)
        timeline = build_timeline(self.db, incident)
        notifications = [e for e in timeline if e["kind"] == "notification"]
        self.assertEqual(len(notifications), 1)
        self.assertIsNone(notifications[0]["device_id"])


class MttaMttrTest(unittest.TestCase):
    def test_format_duration_handles_none_and_seconds(self):
        self.assertEqual(format_duration(None), "n/a")
        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(65), "1m 5s")
        self.assertEqual(format_duration(3661), "1h 1m 1s")

    def test_mtta_uses_the_earliest_acknowledgment_across_members(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(f"{tmp.name}/db.sqlite")
        assert db.initialize()
        cluster_id = db.execute(
            "INSERT INTO alert_clusters(trigger_class,context_key,context_value,context_json,severity,opened_at,last_seen_at,resolved_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("connectivity", "ssid", "Net", "{}", "critical", "2024-01-01T00:00:00+00:00",
             "2024-01-01T00:10:00+00:00", "2024-01-01T00:10:00+00:00"))
        for name, acked in (("a", "2024-01-01T00:02:00+00:00"), ("b", "2024-01-01T00:05:00+00:00")):
            db.execute(
                "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,"
                "resolved_at,acknowledged_at,state,cluster_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (name, "device_offline", "critical", "offline", f"{name}:device_offline:",
                 "2024-01-01T00:00:00+00:00", "2024-01-01T00:10:00+00:00", "2024-01-01T00:10:00+00:00",
                 acked, "resolved", cluster_id))
        cluster = db.rows("SELECT * FROM alert_clusters WHERE cluster_id=?", (cluster_id,))[0]
        incident_id = synthesize_cluster(db, cluster)
        incident = get_incident(db, incident_id)
        self.assertEqual(incident["mtta_seconds"], 120.0)  # earliest ack: 2 minutes in
        self.assertEqual(incident["mttr_seconds"], 600.0)  # opened to resolved: 10 minutes


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.incident = {
            "incident_id": 7, "kind": "alert", "title": "Device Offline · solo", "severity": "critical",
            "opened_at": "2024-01-01T00:00:00+00:00", "resolved_at": "2024-01-01T00:10:00+00:00",
            "mtta_seconds": 120.0, "mttr_seconds": 600.0, "device_ids": ["solo"], "alert_ids": [1],
        }
        self.timeline = [
            {"time": "2024-01-01T00:00:00+00:00", "kind": "alert_opened", "device_id": "solo",
             "description": "Alert opened: Device is offline"},
            {"time": "2024-01-01T00:10:00+00:00", "kind": "alert_resolved", "device_id": "solo",
             "description": "Alert resolved: Device is offline"},
        ]

    def test_json_export_round_trips_incident_and_timeline(self):
        payload = to_json(self.incident, self.timeline)
        self.assertEqual(payload["incident"]["incident_id"], 7)
        self.assertEqual(len(payload["timeline"]), 2)
        json.dumps(payload)  # must be JSON-serializable

    def test_markdown_export_contains_summary_and_timeline_entries(self):
        markdown = to_markdown(self.incident, self.timeline)
        self.assertIn("# Device Offline", markdown)
        self.assertIn("MTTA", markdown)
        self.assertIn("2m 0s", markdown)
        self.assertIn("alert_opened", markdown)
        self.assertIn("alert_resolved", markdown)

    def test_html_export_is_a_standalone_printable_page(self):
        html = to_html(self.incident, self.timeline)
        self.assertIn("<html", html)
        self.assertIn("Device Offline", html)
        self.assertIn("<table>", html)
        self.assertIn("alert_opened", html)
        # User-controlled text must be escaped, not injected raw.
        dangerous = dict(self.incident, title="<script>evil()</script>")
        escaped = to_html(dangerous, self.timeline)
        self.assertNotIn("<script>evil()</script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)


class ApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {}, None)
        self.client = create_app(PiNOCState(), {"TESTING": True}, self.history).test_client()

    def tearDown(self):
        self._tmp.cleanup()

    def stamp(self, offset_seconds):
        return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()

    def _make_incident(self):
        self.history._device(device("solo"), self.stamp(0))
        self.history._device(device("solo", online=False), self.stamp(5))
        self.history._device(device("solo", online=True), self.stamp(10))
        return self.db.scalar("SELECT incident_id FROM incidents WHERE kind='alert'")

    def test_incidents_page_renders(self):
        self.assertEqual(self.client.get("/incidents").status_code, 200)

    def test_incident_detail_page_renders(self):
        incident_id = self._make_incident()
        self.assertEqual(self.client.get(f"/incidents/{incident_id}").status_code, 200)

    def test_list_endpoint_returns_synthesized_incidents(self):
        self._make_incident()
        body = self.client.get("/api/incidents").get_json()
        self.assertEqual(len(body["incidents"]), 1)
        self.assertEqual(body["incidents"][0]["device_ids"], ["solo"])

    def test_list_endpoint_filters_by_device_and_severity(self):
        self._make_incident()
        self.assertEqual(len(self.client.get("/api/incidents?device=solo").get_json()["incidents"]), 1)
        self.assertEqual(len(self.client.get("/api/incidents?device=nope").get_json()["incidents"]), 0)
        self.assertEqual(len(self.client.get("/api/incidents?severity=critical").get_json()["incidents"]), 1)
        self.assertEqual(len(self.client.get("/api/incidents?severity=info").get_json()["incidents"]), 0)

    def test_detail_endpoint_returns_incident_and_timeline(self):
        incident_id = self._make_incident()
        body = self.client.get(f"/api/incidents/{incident_id}").get_json()
        self.assertEqual(body["incident"]["incident_id"], incident_id)
        self.assertGreaterEqual(len(body["timeline"]), 2)

    def test_detail_endpoint_404s_for_unknown_incident(self):
        self.assertEqual(self.client.get("/api/incidents/999999").status_code, 404)

    def test_export_endpoints_return_expected_formats(self):
        incident_id = self._make_incident()
        md = self.client.get(f"/api/incidents/{incident_id}/export.md")
        self.assertEqual(md.status_code, 200)
        self.assertIn("text/markdown", md.content_type)
        self.assertIn("# ", md.get_data(as_text=True))

        payload = self.client.get(f"/api/incidents/{incident_id}/export.json")
        self.assertEqual(payload.status_code, 200)
        self.assertIn("incident", payload.get_json())

        printable = self.client.get(f"/api/incidents/{incident_id}/print")
        self.assertEqual(printable.status_code, 200)
        self.assertIn("text/html", printable.content_type)
        self.assertIn("<table>", printable.get_data(as_text=True))

    def test_resolved_alert_card_links_to_its_incident(self):
        self._make_incident()
        body = self.client.get("/api/alerts?state=resolved").get_json()
        resolved = [a for a in body["alerts"] if a["device_id"] == "solo"]
        self.assertEqual(len(resolved), 1)
        self.assertIsNotNone(resolved[0]["incident_id"])


if __name__ == "__main__":
    unittest.main()
