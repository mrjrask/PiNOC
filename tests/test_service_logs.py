"""Coverage for bounded service-log collection, retention, and the logs API."""
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pi_noc
from pinoc.collectors.fleet import FleetCollector, parse_jlogs, redact_log_line
from pinoc.database import Database
from pinoc.device_config import DeviceConfig
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.security import SecurityManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc

# Minimal complete collection output; the __JLOGS__ section mirrors what the
# device script prints when the __jlogs__ argument is present.
SCRIPT_OUTPUT = """__OS__
PRETTY_NAME="Raspberry Pi OS"
__UNAME__
Linux 6.6 armv7l
__MODEL__
Raspberry Pi 5
__UPTIME__
1000 2000
__LOAD__
1.0 1.0 1.0
__CPU__
cpu 10 0 10 80 0 0 0 0 0 0
__FREQ__
__TEMP__
/sys/class/thermal/thermal_zone0/temp=50000
__THROTTLED__
throttled=0x0
__MEM__
MemTotal: 8000000 kB
MemAvailable: 4000000 kB
SwapTotal: 0 kB
SwapFree: 0 kB
__DF__
Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/mmcblk0p2 ext4 100000 50000 50000 50% /
__MOUNTS__
/dev/mmcblk0p2 / ext4 rw 0 0
__DISKSTATS__
__IOERRORS__
__IOERRORSTATUS__
available
__ROUTE__
__ADDR__
__NET__
iface |bytes
eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0 0
__IW__
__JLOGS__
=== ssh
Jan 01 00:00:01 pi sshd[123]: Accepted publickey for pi
Jan 01 00:00:02 pi sshd[123]: password=hunter2 in env
Jan 01 00:00:03 pi sshd[123]: using Bearer abcdef123456
=== cockpit
Jan 01 00:00:04 pi cockpit: listening
__SERVICES__
__UNITS__
ssh.service enabled
"""


def device_config(**overrides) -> DeviceConfig:
    values = dict(id="pi", hostname="pi", friendly_name="Pi",
                  address="192.168.1.10", collection_method="ssh",
                  monitored_services=["ssh", "cockpit"],
                  critical_services=["ssh"])
    values.update(overrides)
    return DeviceConfig(**values)


def completed(stdout: str) -> "subprocess.CompletedProcess[str]":
    import subprocess
    return subprocess.CompletedProcess(["sh"], 0, stdout, "")


JLOGS_SECTION = """=== ssh
Jan 01 00:00:01 pi sshd[123]: Accepted publickey for pi
Jan 01 00:00:02 pi sshd[123]: password=hunter2 in env
Jan 01 00:00:03 pi sshd[123]: using Bearer abcdef123456
=== cockpit
Jan 01 00:00:04 pi cockpit: listening"""


class ParseJlogsTest(unittest.TestCase):
    def test_parses_units_and_redacts_secrets(self):
        entries = parse_jlogs(JLOGS_SECTION)
        units = [x["unit"] for x in entries]
        self.assertEqual(units, ["ssh", "cockpit"])
        ssh = entries[0]["lines"]
        self.assertEqual(ssh[0], "Jan 01 00:00:01 pi sshd[123]: Accepted publickey for pi")
        self.assertEqual(ssh[1], "Jan 01 00:00:02 pi sshd[123]: password=[REDACTED] in env")
        self.assertEqual(ssh[2], "Jan 01 00:00:03 pi sshd[123]: using [REDACTED]")
        self.assertEqual(entries[1]["lines"], ["Jan 01 00:00:04 pi cockpit: listening"])

    def test_empty_units_are_dropped(self):
        self.assertEqual(parse_jlogs("=== ssh\n\n   \n=== cockpit\nline\n"),
                         [{"unit": "cockpit", "lines": ["line"]}])

    def test_line_length_and_unit_line_caps(self):
        long = "x" * 1000
        entries = parse_jlogs(f"=== ssh\n{long}\n")
        self.assertEqual(len(entries[0]["lines"][0]), 512)
        entries = parse_jlogs("=== ssh\n" + "\n".join(f"line {i}" for i in range(500)))
        self.assertEqual(len(entries[0]["lines"]), 200)
        self.assertEqual(entries[0]["lines"][0], "line 300")

    def test_unit_count_cap(self):
        text = "\n".join(f"=== unit{i}\nline {i}" for i in range(80))
        self.assertEqual(len(parse_jlogs(text)), 50)

    def test_redact_variants(self):
        self.assertIn("[REDACTED]", redact_log_line("token = abc123"))
        self.assertEqual(
            redact_log_line("Authorization: Bearer abcdef123456789"),
            "Authorization: [REDACTED]",
        )
        self.assertNotIn(
            "abcdef123456789",
            redact_log_line("Authorization: Bearer abcdef123456789"),
        )
        for value in (
            "Basic dXNlcjpwYXNz",
            'Digest username="admin", realm="private", response="secret"',
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260920/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123",
        ):
            self.assertEqual(
                redact_log_line(f"Authorization: {value}"),
                "Authorization: [REDACTED]",
            )
        self.assertEqual(
            redact_log_line('{"authorization":"Basic dXNlcjpwYXNz","status":200}'),
            '{"authorization":"[REDACTED]","status":200}',
        )
        self.assertIn("[REDACTED]", redact_log_line("api-key: ab12cd34ef"))
        self.assertEqual(redact_log_line('{"token":"abcdef123456"}'),
                         '{"token":"[REDACTED]"}')
        self.assertEqual(redact_log_line("{'password': 'hunter2'}"),
                         "{'password': '[REDACTED]'}")
        for line, secret in (
            ("DATABASE_PASSWORD=hunter2", "hunter2"),
            ("AWS_SECRET_ACCESS_KEY=aws-secret", "aws-secret"),
            ("GITHUB_TOKEN=github-secret", "github-secret"),
            ("client_secret=client-secret", "client-secret"),
            ('{"access_token":"access-secret"}', "access-secret"),
            ("HTTP_AUTHORIZATION=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ):
            redacted = redact_log_line(line)
            self.assertIn("[REDACTED]", redacted)
            self.assertNotIn(secret, redacted)
        self.assertEqual(
            redact_log_line("key -----BEGIN PRIVATE KEY-----MIIE-----END PRIVATE KEY-----"),
            "key [REDACTED-KEY]")
        self.assertEqual(redact_log_line("plain line"), "plain line")

    def test_multiline_private_key_is_redacted_before_lines_are_split(self):
        entries = parse_jlogs("""=== ssh
Jan 01 sshd: key follows -----BEGIN PRIVATE KEY-----
MIIE-sensitive-material
-----END PRIVATE KEY----- trailing text
Jan 01 sshd: safe line""")

        self.assertEqual(entries, [{"unit": "ssh", "lines": [
            "Jan 01 sshd: key follows [REDACTED-KEY] trailing text",
            "Jan 01 sshd: safe line",
        ]}])


class CommandCadenceTest(unittest.TestCase):
    def _collector(self, log_tail_seconds=300.0, **overrides):
        return FleetCollector([device_config(**overrides)], runner=lambda *a, **k: None,
                              timeout=1, log_tail_seconds=log_tail_seconds, log_tail_lines=10)

    def test_argument_present_when_due(self):
        collector = self._collector()
        args = collector._command(device_config(), jlogs_due=True)
        self.assertIn("__jlogs__:10:ssh,cockpit", args)

    def test_argument_absent_when_not_due(self):
        collector = self._collector()
        args = collector._command(device_config(), jlogs_due=False)
        self.assertFalse(any(a.startswith("__jlogs__") for a in args))

    def test_malicious_units_are_excluded(self):
        collector = self._collector()
        device = device_config(monitored_services=["ssh;rm", "bad name", "ok.service@1"],
                              critical_services=["ssh"])
        args = collector._command(device, jlogs_due=True)
        sentinel = [a for a in args if a.startswith("__jlogs__:")]
        self.assertEqual(sentinel, ["__jlogs__:10:ok.service@1,ssh"])

    def test_units_capped_at_ten(self):
        units = [f"unit{i}" for i in range(30)]
        collector = self._collector()
        args = collector._command(device_config(monitored_services=units), jlogs_due=True)
        sentinel = [a for a in args if a.startswith("__jlogs__:")][0]
        self.assertEqual(len(sentinel.split(":")[2].split(",")), 10)

    def test_collect_preserves_previous_logs_until_next_cycle(self):
        device = device_config()
        seen = []

        def runner(args, **kwargs):
            seen.append(list(args))
            return completed(SCRIPT_OUTPUT)

        collector = FleetCollector([device], runner=runner, timeout=1,
                                   log_tail_seconds=300, log_tail_lines=10)
        first = collector.collect_device(device)
        self.assertTrue(any(a.startswith("__jlogs__") for a in seen[-1]))
        self.assertEqual([x["unit"] for x in first.logs], ["ssh", "cockpit"])

        collector._last_jlogs[device.id] = time.monotonic()  # cadence not yet due
        second = collector.collect_device(device)
        self.assertFalse(any(a.startswith("__jlogs__") for a in seen[-1]))
        self.assertEqual(second.logs, first.logs)

        collector._last_jlogs[device.id] = time.monotonic() - 301
        third = collector.collect_device(device)
        self.assertTrue(any(a.startswith("__jlogs__") for a in seen[-1]))

    def test_coordinator_passes_log_settings_without_replacing_runner(self):
        polling = {"log_tail_seconds": 450, "log_tail_lines": 75}
        with patch.object(pi_noc, "load_devices", return_value=([], [])), \
                patch.object(pi_noc, "read_env_value", return_value="password"), \
                patch.dict(pi_noc.CONFIG, {"polling": polling}):
            collector = pi_noc.SharedSnapshotCoordinator(PiNOCState()).fleet_collector

        self.assertIs(collector.runner, pi_noc.subprocess.run)
        self.assertEqual(collector.log_tail_seconds, 450)
        self.assertEqual(collector.log_tail_lines, 75)
        self.assertEqual(collector.password, "password")


class HistoryLogStorageTest(unittest.TestCase):
    def test_ring_pruning_keeps_latest_per_unit(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            history = HistoryManager(db, {"log_ring_samples": 5})
            for i in range(12):
                stamp = (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=i)).isoformat()
                history._sample({"id": "pi", "online": True,
                                 "logs": [{"unit": "ssh", "lines": [f"line {i}"]}]}, stamp)
            rows = db.rows("SELECT * FROM service_logs ORDER BY id DESC")
            self.assertEqual(len(rows), 5)
            self.assertEqual([x["lines"] for x in rows],
                             [f"line {i}" for i in range(11, 6, -1)])

    def test_offline_or_empty_logs_are_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            history = HistoryManager(db, {})
            history._sample({"id": "pi", "online": False,
                             "logs": [{"unit": "ssh", "lines": ["x"]}]}, "2026-01-01T00:00:00+00:00")
            history._sample({"id": "pi", "online": True,
                             "logs": [{"unit": "", "lines": []}]}, "2026-01-01T00:01:00+00:00")
            self.assertEqual(db.scalar("SELECT COUNT(*) FROM service_logs"), 0)

    def test_retention_removes_old_samples(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                       ("2025-01-01T00:00:00+00:00", "pi", "ssh", "old"))
            db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                       ("2026-01-01T00:00:00+00:00", "pi", "ssh", "new"))
            HistoryManager(db, {}).maintenance(datetime(2026, 1, 2, tzinfo=UTC))
            rows = db.rows("SELECT * FROM service_logs")
            self.assertEqual([x["lines"] for x in rows], ["new"])


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


class LogsApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name)
        self.db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                        ("2026-01-01T00:00:00+00:00", "pi", "ssh", "line one\npassword=hunter2\nline three"))
        self.db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                        ("2026-01-01T01:00:00+00:00", "pi", "ssh", "newer line\nBearer abcdef123456"))
        self.db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                        ("2026-01-01T02:00:00+00:00", "pi", "cockpit", "cockpit line"))
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def test_unit_summary(self):
        payload = self.client.get("/api/devices/pi/logs").get_json()
        self.assertIsNone(payload["unit"])
        self.assertEqual([x["unit"] for x in payload["units"]], ["cockpit", "ssh"])
        latest = [x for x in payload["units"] if x["unit"] == "ssh"][0]
        self.assertEqual(latest["last_timestamp"], "2026-01-01T01:00:00+00:00")
        self.assertEqual(latest["line_count"], 2)

    def test_unit_samples_are_redacted_on_read(self):
        payload = self.client.get("/api/devices/pi/logs?unit=ssh").get_json()
        self.assertEqual(payload["unit"], "ssh")
        self.assertEqual(len(payload["samples"]), 2)
        self.assertEqual(payload["samples"][0]["lines"], ["newer line", "[REDACTED]"])
        self.assertEqual(payload["samples"][1]["lines"], ["line one", "password=[REDACTED]", "line three"])

    def test_multiline_private_key_already_in_storage_is_redacted_on_read(self):
        self.db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                        ("2026-01-01T03:00:00+00:00", "pi", "ssh",
                         "key -----BEGIN PRIVATE KEY-----\nMIIE-sensitive-material\n"
                         "-----END PRIVATE KEY----- done\nsafe line"))

        payload = self.client.get("/api/devices/pi/logs?unit=ssh&samples=1").get_json()

        self.assertEqual(payload["samples"][0]["lines"],
                         ["key [REDACTED-KEY] done", "safe line"])

    def test_samples_parameter_is_bounded(self):
        for value in ("0", "500", "abc"):
            payload = self.client.get(f"/api/devices/pi/logs?unit=ssh&samples={value}").get_json()
            self.assertLessEqual(len(payload["samples"]), 100)
        self.assertEqual(len(self.client.get("/api/devices/pi/logs?unit=ssh&samples=1").get_json()["samples"]), 1)
        self.assertEqual(self.client.get("/api/devices/pi/logs?unit=missing").get_json()["samples"], [])

    def test_503_without_history(self):
        with tempfile.TemporaryDirectory() as folder:
            app, _ = build(folder, with_history=False)
            self.assertEqual(app.test_client().get("/api/devices/pi/logs").status_code, 503)


class LogsGatingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db = build(self._tmp.name, enabled=True)
        self.db.execute("INSERT INTO service_logs(timestamp,device_id,unit,lines) VALUES(?,?,?,?)",
                        ("2026-01-01T00:00:00+00:00", "pi", "ssh", "line"))
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        self.security.create_user("person", "correct horse battery", "administrator")
        self.security.create_user("watcher", "correct horse battery", "viewer")
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

    def test_token_scopes(self):
        history_token = self.security.create_token("person", ["read:history"])
        fleet_token = self.security.create_token("person", ["read:fleet"])
        alerts_token = self.security.create_token("person", ["read:alerts"])
        self.assertEqual(self.client.get("/api/devices/pi/logs", headers={"Authorization": "Bearer " + history_token}).status_code, 200)
        self.assertEqual(self.client.get("/api/devices/pi/logs?unit=ssh", headers={"Authorization": "Bearer " + history_token}).status_code, 200)
        self.assertEqual(self.client.get("/api/devices/pi/logs", headers={"Authorization": "Bearer " + fleet_token}).status_code, 403)
        self.assertEqual(self.client.get("/api/devices/pi/logs", headers={"Authorization": "Bearer " + alerts_token}).status_code, 403)
        self.assertEqual(self.client.get("/api/devices/pi/logs").status_code, 401)

    def test_fleet_endpoints_do_not_expose_collected_logs(self):
        fleet_token = self.security.create_token("person", ["read:fleet"])
        headers = {"Authorization": "Bearer " + fleet_token}

        devices = self.client.get("/api/devices", headers=headers).get_json()["devices"]
        device = self.client.get("/api/devices/pi", headers=headers).get_json()

        self.assertNotIn("logs", devices[0])
        self.assertNotIn("logs", device)

    def test_viewer_session_can_read(self):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        self.assertEqual(
            self.client.post("/login", data={"username": "watcher", "password": "correct horse battery",
                                              "csrf_token": csrf}).status_code, 302)
        self.assertEqual(self.client.get("/api/devices/pi/logs").status_code, 200)


if __name__ == "__main__":
    unittest.main()
