"""Coverage for scheduled fleet health reports (pinoc/reports.py).

Six layers:

* :class:`ConfigValidationTest` -- ``parse_report``/``validate_reports``
  against good and bad ``reports`` config sections, including the
  channel_id-must-reference-a-configured-channel check
  ``pinoc.config_store.validate_reports`` wires up;
* :class:`ScopeResolutionTest` -- ``resolve_scope_devices`` (fleet/role/tag)
  against a fake device roster;
* :class:`SectionRenderingTest` -- each pure content-section builder
  (uptime, alerts, capacity, storage_media, patch_status) against fake
  state/history data and a real ``Database``;
* :class:`RenderingTest` -- ``render_html``/``render_csv``/``summarize``
  against a built section set;
* :class:`ServiceTest` -- ``ReportService.tick()``/``generate()`` firing a
  due report, delivering it through a real ``NotificationService`` (with an
  injected fake sender, exercising the exact send path), and archiving the
  edition -- plus one-shot consumption and edition retention pruning;
* :class:`WebTest` -- the ``/reports`` page and ``/api/reports*`` endpoints
  through ``create_app`` + Flask's test client.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.database import Database, utcnow
from pinoc.models import DeviceState
from pinoc.notifications import NotificationService
from pinoc.reports import (
    ReportConfigError, ReportService, alerts_section, build_sections,
    capacity_section, parse_report, patch_status_section, render_csv,
    render_html, resolve_scope_devices, storage_media_section, summarize,
    uptime_section, validate_reports,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc


def valid_report(**overrides):
    base = {"id": "weekly-fleet", "name": "Weekly fleet health", "spec": "@weekly",
            "scope": {"type": "fleet"}, "channel_id": "ops", "sections": ["uptime", "alerts"]}
    base.update(overrides)
    return base


def make_device(device_id, **overrides):
    base = dict(id=device_id, hostname=device_id, friendly_name=device_id.title(),
                roles=[], tags=[], online=True, health="healthy")
    base.update(overrides)
    return DeviceState(**base)


class ConfigValidationTest(unittest.TestCase):
    def test_parses_minimal_definition_with_defaults(self):
        parsed = parse_report(valid_report(), 0)
        self.assertEqual(parsed["id"], "weekly-fleet")
        self.assertEqual(parsed["format"], "html")
        self.assertEqual(parsed["window_days"], 7)
        self.assertTrue(parsed["enabled"])
        self.assertEqual(parsed["scope"], {"type": "fleet", "value": None})

    def test_rejects_missing_id(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(id=""), 0)

    def test_rejects_bad_spec(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(spec="not a cron"), 0)

    def test_rejects_unknown_scope_type(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(scope={"type": "device", "value": "x"}), 0)

    def test_role_scope_requires_known_role(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(scope={"type": "role", "value": "ghost"}), 0,
                        known_roles={"file_server"})
        parse_report(valid_report(scope={"type": "role", "value": "file_server"}), 0,
                    known_roles={"file_server"})

    def test_missing_channel_id_rejected(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(channel_id=""), 0)

    def test_unknown_channel_id_rejected_when_channels_known(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(channel_id="ghost"), 0, known_channel_ids={"ops"})
        parse_report(valid_report(channel_id="ops"), 0, known_channel_ids={"ops"})

    def test_rejects_unknown_section(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(sections=["not-a-section"]), 0)

    def test_rejects_bad_format(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(format="pdf"), 0)

    def test_rejects_window_days_out_of_range(self):
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(window_days=0), 0)
        with self.assertRaises(ReportConfigError):
            parse_report(valid_report(window_days=91), 0)

    def test_validate_reports_accepts_none(self):
        validate_reports({})

    def test_validate_reports_rejects_duplicate_ids(self):
        with self.assertRaises(ReportConfigError):
            validate_reports({"reports": {"definitions": [valid_report(), valid_report()]}})

    def test_validate_reports_bad_interval(self):
        with self.assertRaises(ReportConfigError):
            validate_reports({"reports": {"interval_seconds": 1}})

    def test_config_store_wires_channel_check(self):
        from pinoc.config_store import validate_reports as store_validate_reports
        value = {"notifications": {"channels": [{"id": "ops", "kind": "webhook", "url": "https://x"}]},
                 "reports": {"definitions": [valid_report(channel_id="ops")]}}
        store_validate_reports(value, set(), set())
        bad = {"notifications": {"channels": []},
               "reports": {"definitions": [valid_report(channel_id="ghost")]}}
        with self.assertRaises(ValueError):
            store_validate_reports(bad, set(), set())


class ScopeResolutionTest(unittest.TestCase):
    def setUp(self):
        self.devices = [
            {"id": "a", "roles": ["file_server"], "tags": ["rpi4"]},
            {"id": "b", "roles": ["camera"], "tags": ["rpi4", "outdoor"]},
            {"id": "c", "roles": [], "tags": []},
        ]

    def test_fleet_scope_returns_every_device(self):
        self.assertEqual(resolve_scope_devices({"type": "fleet"}, self.devices), ["a", "b", "c"])

    def test_role_scope(self):
        self.assertEqual(resolve_scope_devices({"type": "role", "value": "camera"}, self.devices), ["b"])

    def test_tag_scope(self):
        self.assertEqual(resolve_scope_devices({"type": "tag", "value": "rpi4"}, self.devices), ["a", "b"])

    def test_unknown_scope_type_resolves_empty(self):
        self.assertEqual(resolve_scope_devices({"type": "device", "value": "a"}, self.devices), [])


class SectionRenderingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.now = datetime.now(UTC)
        self.devices_by_id = {
            "a": {"id": "a", "friendly_name": "Device A", "online": True,
                  "media": [{"device": "mmcblk0", "media_errors": True, "io_errors": 12}],
                  "applications": {"packages": {"updates_available": 4}}, "kernel": "6.1.0"},
            "b": {"id": "b", "friendly_name": "Device B", "online": False,
                  "media": [], "applications": {"packages": {"updates_available": 0}}, "kernel": "6.1.0"},
        }

    def _health_sample(self, device_id, seconds_ago, health):
        ts = (self.now - timedelta(seconds=seconds_ago)).isoformat()
        self.db.execute("INSERT INTO health_samples(timestamp,device_id,health,online) VALUES(?,?,?,?)",
                        (ts, device_id, health, 1 if health not in ("offline",) else 0))

    def test_uptime_section_computes_attainment(self):
        for i in range(10):
            self._health_sample("a", i * 3600, "healthy")
        result = uptime_section(self.db, ["a", "b"], self.devices_by_id, 7, self.now)
        self.assertEqual(result["window_days"], 7)
        by_id = {r["device_id"]: r for r in result["devices"]}
        self.assertEqual(by_id["a"]["online"], True)
        self.assertIsNotNone(by_id["a"]["attainment_percent"])
        self.assertIsNone(by_id["b"]["attainment_percent"])  # no samples for b

    def test_uptime_section_without_db_is_insufficient(self):
        result = uptime_section(None, ["a"], self.devices_by_id, 7, self.now)
        self.assertIsNone(result["fleet_attainment_percent"])

    def test_alerts_section_counts_and_ranks(self):
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,"
            "metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            ("a", "high_cpu", "warning", "CPU high", "a:high_cpu:", stamp, stamp, "active", "{}"))
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,last_seen_at,state,"
            "metadata_json) VALUES(?,?,?,?,?,?,?,?,?)",
            ("a", "critical_temperature", "critical", "Too hot", "a:critical_temperature:", stamp, stamp,
             "active", "{}"))
        result = alerts_section(self.db, ["a", "b"], 7, self.now)
        self.assertEqual(result["open_count"], 2)
        self.assertEqual(result["open_by_severity"]["critical"], 1)
        self.assertEqual(result["open_by_device"]["a"], 2)
        # ranked critical first
        self.assertEqual(result["top_open"][0]["severity"], "critical")

    def test_alerts_section_empty_scope(self):
        result = alerts_section(self.db, [], 7, self.now)
        self.assertEqual(result["open_count"], 0)

    def test_capacity_section_reports_forecast(self):
        for i in range(10):
            ts = (self.now - timedelta(days=9 - i)).isoformat()
            used = 1_000_000 + i * 100_000_000
            self.db.execute(
                "INSERT INTO storage_metrics(timestamp,device_id,device,mount_point,filesystem,total_bytes,"
                "used_bytes,available_bytes,percent_used,read_only) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ts, "a", "sda1", "/", "ext4", 10_000_000_000, used, 10_000_000_000 - used,
                 used * 100.0 / 10_000_000_000, 0))
        result = capacity_section(self.db, ["a"], self.devices_by_id, self.now)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mount_point"], "/")
        self.assertIn(result[0]["status"], ("growing", "stable", "decreasing"))

    def test_storage_media_section_reads_live_snapshot(self):
        result = storage_media_section(self.devices_by_id, ["a", "b"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["device_id"], "a")
        self.assertTrue(result[0]["media_errors"])

    def test_patch_status_section_reads_packages_and_rollout(self):
        stamp = utcnow()
        self.db.execute(
            "INSERT INTO rollout_runs(run_id,name,scope,status,current_wave,wave_count,requested_by,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("run1", "test", "all", "completed", 0, 1, "tester", stamp, stamp))
        self.db.execute(
            "INSERT INTO rollout_devices(run_id,device_id,wave,status,updated_at) VALUES(?,?,?,?,?)",
            ("run1", "a", 0, "succeeded", stamp))
        result = patch_status_section(self.db, self.devices_by_id, ["a", "b"])
        by_id = {r["device_id"]: r for r in result}
        self.assertEqual(by_id["a"]["updates_available"], 4)
        self.assertEqual(by_id["a"]["last_rollout_status"], "succeeded")
        self.assertIsNone(by_id["b"]["last_rollout_status"])

    def test_build_sections_resolves_scope_and_all_requested_sections(self):
        state = PiNOCState()
        state.publish([make_device("a", roles=["file_server"]), make_device("b", roles=[])])
        definition = valid_report(sections=["uptime", "alerts", "capacity", "storage_media", "patch_status"],
                                  scope={"type": "role", "value": "file_server"})
        built = build_sections(parse_report(definition, 0), self.db, state, self.now)
        self.assertEqual(built["device_ids"], ["a"])
        for name in ("uptime", "alerts", "capacity", "storage_media", "patch_status"):
            self.assertIn(name, built["sections"])


class RenderingTest(unittest.TestCase):
    def setUp(self):
        self.definition = parse_report(valid_report(sections=["uptime", "alerts"]), 0)
        self.built = {
            "device_ids": ["a", "b"],
            "sections": {
                "uptime": {"window_days": 7, "fleet_attainment_percent": 99.5,
                          "devices": [{"device_id": "a", "name": "Device A", "online": True,
                                       "attainment_percent": 99.9},
                                      {"device_id": "b", "name": "Device B", "online": False,
                                       "attainment_percent": 90.0}]},
                "alerts": {"open_count": 1, "open_by_severity": {"critical": 1}, "open_by_device": {"a": 1},
                          "opened_count": 1, "resolved_count": 0,
                          "top_open": [{"device_id": "a", "alert_type": "critical_temperature",
                                        "severity": "critical", "message": "Too hot", "opened_at": "now"}]},
            },
        }

    def test_render_html_includes_sections(self):
        html = render_html(self.definition, self.built, "2026-09-23T00:00:00+00:00")
        self.assertIn("Weekly fleet health", html)
        self.assertIn("Uptime", html)
        self.assertIn("Alert summary", html)
        self.assertIn("Device A", html)
        self.assertIn("Too hot", html)

    def test_render_html_escapes_content(self):
        evil = dict(self.definition, name="<script>alert(1)</script>")
        html = render_html(evil, self.built, "now")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_render_csv_has_one_row_per_device(self):
        csv_text = render_csv(self.definition, self.built)
        lines = csv_text.strip().splitlines()
        self.assertEqual(len(lines), 3)  # header + 2 devices
        self.assertIn("device_id", lines[0])
        self.assertIn("open_alerts", lines[0])

    def test_summarize_mentions_open_alerts_and_device_count(self):
        text = summarize(self.built)
        self.assertIn("2 device(s)", text)
        self.assertIn("1 alert(s) open", text)


class FakeNotifications:
    """A minimal stand-in exposing exactly the surface ReportService uses
    (``channels()``/``send_direct``), for tests that don't need a real
    NotificationService end to end (see ServiceTest for that)."""

    def __init__(self, channels, sender):
        self._channels = channels
        self.sender = sender

    def channels(self):
        return list(self._channels)

    def send_direct(self, channel, subject, body):
        return self.sender(channel, subject, body)


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([make_device("a"), make_device("b")])
        self.sent = []
        # A real NotificationService, with a fake sender injected -- exercises
        # ReportService._deliver -> NotificationService.send_direct -> _send
        # (the real code path) all the way, per the module's own reuse claim.
        self.notifications = NotificationService(
            {"enabled": True, "channels": [{"id": "ops", "kind": "webhook", "url": "https://example/hook",
                                            "enabled": True}]},
            sender=lambda kind, channel, message: self.sent.append((kind, channel, message)) or (True, None))

    def _service(self, **config_overrides):
        config = {"definitions": [valid_report(sections=["uptime", "alerts"])]}
        config.update(config_overrides)
        return ReportService(self.db, state=self.state, notifications=self.notifications, config=config,
                             interval=9999)

    def test_generate_renders_delivers_and_archives(self):
        service = self._service()
        edition_id = service.run_now("weekly-fleet")
        self.assertEqual(len(self.sent), 1)
        kind, channel, message = self.sent[0]
        self.assertEqual(kind, "webhook")
        self.assertTrue(message["body"])
        self.assertIn("device(s) in scope", message["body"])
        self.assertTrue(message["subject"].startswith("PiNOC report:"))
        edition = service.edition(edition_id)
        self.assertEqual(edition["report_id"], "weekly-fleet")
        self.assertEqual(edition["delivered"], 1)
        self.assertIn("<h1>", edition["content"])

    def test_run_now_unknown_report_raises(self):
        service = self._service()
        with self.assertRaises(ValueError):
            service.run_now("does-not-exist")

    def test_delivery_failure_is_recorded_but_edition_still_archived(self):
        failing = NotificationService(
            {"enabled": True, "channels": [{"id": "ops", "kind": "webhook", "url": "https://example/hook"}]},
            sender=lambda kind, channel, message: (False, "boom"))
        service = ReportService(self.db, state=self.state, notifications=failing,
                                config={"definitions": [valid_report()]}, interval=9999)
        edition_id = service.run_now("weekly-fleet")
        edition = service.edition(edition_id)
        self.assertEqual(edition["delivered"], 0)
        self.assertEqual(edition["delivery_error"], "boom")

    def test_missing_channel_reports_delivery_error(self):
        service = ReportService(self.db, state=self.state, notifications=self.notifications,
                                config={"definitions": [valid_report(channel_id="ghost")]}, interval=9999)
        edition_id = service.run_now("weekly-fleet")
        edition = service.edition(edition_id)
        self.assertEqual(edition["delivered"], 0)
        self.assertIn("ghost", edition["delivery_error"])

    def test_tick_fires_due_report_and_reschedules(self):
        now = datetime.now(UTC)
        service = self._service()
        # First tick with `now` in the past relative to the next @weekly slot
        # establishes report_schedule_state; force it due by writing a past
        # next_run directly (avoids depending on wall-clock timing).
        service.tick(now)
        self.db.execute("UPDATE report_schedule_state SET next_run=? WHERE report_id=?",
                        ((now - timedelta(seconds=1)).isoformat(), "weekly-fleet"))
        service.tick(now)
        editions = service.editions("weekly-fleet")
        self.assertEqual(len(editions), 1)
        row = self.db.rows("SELECT * FROM report_schedule_state WHERE report_id=?", ("weekly-fleet",))[0]
        self.assertIsNotNone(row["next_run"])
        self.assertGreater(datetime.fromisoformat(row["next_run"]), now)

    def test_one_shot_report_fires_once_then_never_again(self):
        now = datetime.now(UTC)
        target = now + timedelta(seconds=30)
        once_spec = f"once:{target.isoformat()}"
        service = ReportService(self.db, state=self.state, notifications=self.notifications,
                                config={"definitions": [valid_report(spec=once_spec)]}, interval=9999)
        service.tick(now)  # establishes next_run = target; not due yet
        self.assertEqual(len(service.editions("weekly-fleet")), 0)
        service.tick(target + timedelta(seconds=1))  # now due
        self.assertEqual(len(service.editions("weekly-fleet")), 1)
        row = self.db.rows("SELECT * FROM report_schedule_state WHERE report_id=?", ("weekly-fleet",))[0]
        self.assertIsNone(row["next_run"])
        service.tick(target + timedelta(days=1))
        self.assertEqual(len(service.editions("weekly-fleet")), 1)  # not fired again

    def test_edition_retention_prunes_oldest(self):
        service = ReportService(self.db, state=self.state, notifications=self.notifications,
                                config={"definitions": [valid_report()], "edition_retention": 2}, interval=9999)
        now = datetime.now(UTC)
        for i in range(4):
            service.generate(service.get_definition("weekly-fleet"), now=now + timedelta(seconds=i))
        remaining = service.editions("weekly-fleet", limit=10)
        self.assertEqual(len(remaining), 2)

    def test_invalid_definition_in_config_is_skipped_not_fatal(self):
        service = ReportService(self.db, state=self.state, notifications=self.notifications,
                                config={"definitions": [valid_report(), {"id": "bad", "spec": "nonsense"}]},
                                interval=9999)
        self.assertEqual([d["id"] for d in service.definitions], ["weekly-fleet"])


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        from pinoc.history import HistoryManager
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([make_device("a")])
        config = {
            "TESTING": True, "DATABASE": self.db,
            "PINOC_CONFIG": {
                "notifications": {"enabled": True, "channels": [{"id": "ops", "kind": "webhook",
                                                                  "url": "https://example/hook"}]},
                "reports": {"definitions": [valid_report(channel_id="ops")]},
            },
        }
        self.app = create_app(self.state, config, self.history, None,
                              notifications=NotificationService(config["PINOC_CONFIG"]["notifications"],
                                                                 sender=lambda *a: (True, None)))
        self.client = self.app.test_client()

    def _csrf(self):
        self.client.get("/reports")
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path):
        return self.client.post(path, json={}, headers={"X-CSRF-Token": self._csrf()})

    def test_reports_page_renders(self):
        resp = self.client.get("/reports")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Scheduled fleet health reports", resp.data)

    def test_api_reports_lists_configured_report(self):
        resp = self.client.get("/api/reports")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(len(body["reports"]), 1)
        self.assertEqual(body["reports"][0]["id"], "weekly-fleet")

    def test_run_now_creates_edition_visible_in_archive(self):
        resp = self._post("/api/reports/weekly-fleet/run")
        self.assertEqual(resp.status_code, 201)
        edition_id = resp.get_json()["edition_id"]
        listed = self.client.get("/api/reports/editions").get_json()
        self.assertEqual(len(listed["editions"]), 1)
        detail = self.client.get(f"/api/reports/editions/{edition_id}").get_json()
        self.assertEqual(detail["edition"]["report_id"], "weekly-fleet")
        download = self.client.get(f"/api/reports/editions/{edition_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers.get("Content-Disposition", ""))

    def test_run_now_unknown_report_is_404(self):
        resp = self._post("/api/reports/does-not-exist/run")
        self.assertEqual(resp.status_code, 404)

    def test_missing_edition_is_404(self):
        resp = self.client.get("/api/reports/editions/999999")
        self.assertEqual(resp.status_code, 404)

    def test_api_reports_without_service_is_empty(self):
        app = create_app(self.state, {"TESTING": True, "DATABASE": self.db}, self.history, None)
        client = app.test_client()
        resp = client.get("/api/reports")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"running": False, "reports": []})


if __name__ == "__main__":
    unittest.main()
