"""Unit and integration coverage for the user-defined probe integration."""
import socket
import subprocess
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

from pinoc.collectors.fleet import FleetCollector
from pinoc.collectors.probes import ProbeCollector
from pinoc.database import Database, utcnow
from pinoc.device_config import DeviceConfig, DeviceConfigError, parse_device
from pinoc.integrations import probe
from pinoc.models import DeviceState
from pinoc.state import PiNOCState


def valid_http_check(**overrides):
    check = {"name": "api", "kind": "http_get", "url": "http://192.168.1.50:8080/health",
             "timeout_seconds": 5, "interval_seconds": 60}
    check.update(overrides)
    return probe.validate_check(check)


def valid_tcp_check(**overrides):
    check = {"name": "db", "kind": "tcp", "host": "192.168.1.50", "port": 5432}
    check.update(overrides)
    return probe.validate_check(check)


class FakeHTTPResponse:
    def __init__(self, status=200, body="ok"):
        self.status = status
        self._body = body.encode()

    def read(self, limit):
        return self._body

    def close(self):
        pass


class FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, code, body="boom"):
        super().__init__("http://127.0.0.1/", code, "forced error", None, None)
        self._body = body.encode()

    def read(self, limit):
        return self._body


class ValidationTest(unittest.TestCase):
    def test_http_and_tcp_normalize(self):
        http = valid_http_check()
        self.assertEqual((http["kind"], http["timeout_seconds"], http["interval_seconds"]),
                          ("http_get", 5.0, 60.0))
        self.assertEqual(http["expected_status"], [200])
        self.assertEqual(valid_tcp_check()["port"], 5432)
        self.assertEqual(valid_http_check(expected_status=[200, 204])["expected_status"], [200, 204])

    def test_rejects_invalid_entries(self):
        cases = [
            {"kind": "curl"},
            {"kind": "http_get", "url": "ftp://host/x"},
            {"kind": "http_get", "url": "host/no-scheme"},
            {"kind": "http_get", "url": "http://user:pw@host/"},
            {"kind": "http_get", "url": "http://host/", "port": 1},
            {"kind": "tcp", "port": 80},
            {"kind": "tcp", "host": "h", "port": 70000},
            {"kind": "tcp", "host": "h"},
            {"kind": "http_get", "url": "http://h/", "timeout_seconds": 900},
            {"kind": "http_get", "url": "http://h/", "interval_seconds": 0.01},
            {"kind": "http_get", "url": "http://h/", "pattern": "("},
            {"kind": "http_get", "url": "http://h/", "pattern": "a" * 501},
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(probe.ProbeConfigError):
                    probe.validate_check(case)

    def test_name_required_and_unique(self):
        with self.assertRaises(probe.ProbeConfigError):
            probe.validate_check({"kind": "tcp", "host": "h", "port": 1})
        with self.assertRaises(probe.ProbeConfigError):
            probe.validate_probes("pi", {"checks": [
                {"name": "a", "kind": "tcp", "host": "h", "port": 1},
                {"name": "a", "kind": "tcp", "host": "h", "port": 2}]})
        with self.assertRaises(probe.ProbeConfigError):
            probe.validate_probes("pi", {"checks": [
                {"name": f"c{i}", "kind": "tcp", "host": "h", "port": 1} for i in range(21)]})

    def test_device_config_accepts_and_rejects_probe(self):
        device = parse_device({"hostname": "pi", "integrations": {"probe": {
            "checks": [{"name": "api", "kind": "http_get", "url": "http://x/"}]}}}, 0)
        self.assertEqual(device.integrations["probe"]["checks"][0]["interval_seconds"], 60.0)
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "integrations": {"probe": True}}, 0)
        with self.assertRaisesRegex(DeviceConfigError, "kind must be"):
            parse_device({"hostname": "pi", "integrations": {"probe": {
                "checks": [{"name": "x", "kind": "telnet", "host": "h", "port": 1}]}}}, 0)


class RunCheckTest(unittest.TestCase):
    def test_http_success_with_pattern(self):
        check = valid_http_check(pattern="status.*ok")
        result = probe.run_check(check, opener=lambda request, timeout: FakeHTTPResponse(200, '{"status": "ok"}'),
                                 now="2026-01-01T00:00:00+00:00")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertIsNotNone(result["latency_ms"])

    def test_http_wrong_status_and_pattern_mismatch(self):
        check = valid_http_check()
        result = probe.run_check(check, opener=lambda request, timeout: FakeHTTPResponse(500, "x"),
                                 now="2026-01-01T00:00:00+00:00")
        self.assertFalse(result["ok"])
        self.assertIn("unexpected status 500", result["error"])
        check = valid_http_check(pattern="good")
        result = probe.run_check(check, opener=lambda request, timeout: FakeHTTPResponse(200, "bad"),
                                 now="2026-01-01T00:00:00+00:00")
        self.assertFalse(result["ok"])
        self.assertIn("pattern", result["error"])

    def test_http_transport_error_and_expected_5xx(self):
        def boom(request, timeout):
            raise OSError("connection refused")
        self.assertFalse(probe.run_check(valid_http_check(), opener=boom,
                                         now="2026-01-01T00:00:00+00:00")["ok"])
        check = valid_http_check(expected_status=[503])

        def flaky(request, timeout):
            raise FakeHTTPError(503)
        self.assertTrue(probe.run_check(check, opener=flaky,
                                        now="2026-01-01T00:00:00+00:00")["ok"])

    def test_tcp_success_and_failure(self):
        self.assertTrue(probe.run_check(valid_tcp_check(),
                                        connector=lambda address, timeout: socket.socket(),
                                        now="2026-01-01T00:00:00+00:00")["ok"])

        def refuse(address, timeout):
            raise ConnectionRefusedError
        result = probe.run_check(valid_tcp_check(), connector=refuse,
                                 now="2026-01-01T00:00:00+00:00")
        self.assertFalse(result["ok"])
        self.assertIn("connection", result["error"])

    def test_real_local_server_end_to_end(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            check = valid_http_check(url=f"http://127.0.0.1:{port}/health",
                                     pattern="status.*ok")
            result = probe.run_check(check)
            self.assertTrue(result["ok"], result["error"])
            tcp = valid_tcp_check(host="127.0.0.1", port=port)
            self.assertTrue(probe.run_check(tcp)["ok"])
        finally:
            server.shutdown()
            server.server_close()


class NormalizeTest(unittest.TestCase):
    NOW = "2026-01-01T00:00:00+00:00"

    def _probes(self):
        return {"checks": [valid_http_check(), valid_tcp_check(critical=True)]}

    def test_all_pass_is_healthy_without_conditions(self):
        results = [probe.run_check(valid_http_check(),
                                   opener=lambda request, timeout: FakeHTTPResponse(),
                                   now=self.NOW),
                   probe.run_check(valid_tcp_check(),
                                   connector=lambda address, timeout: socket.socket(),
                                   now=self.NOW)]
        status = probe.normalize(self._probes(), results, now=self.NOW)
        self.assertEqual(status["health"], "healthy")
        self.assertEqual(status["conditions"], [])
        self.assertEqual(status["data"]["failed_checks"], 0)

    def test_failed_checks_open_one_explainable_condition(self):
        failing = {"name": "db", "kind": "tcp", "ok": False, "status": None,
                   "latency_ms": 1.0, "error": "connection failed", "checked_at": self.NOW}
        passing = {"name": "api", "kind": "http_get", "ok": True, "status": 200,
                   "latency_ms": 2.0, "error": None, "checked_at": self.NOW}
        status = probe.normalize(self._probes(), [passing, failing], now=self.NOW)
        self.assertEqual(status["health"], "critical")
        self.assertEqual(len(status["conditions"]), 1)
        condition = status["conditions"][0]
        self.assertEqual(condition["type"], "probe_failed")
        self.assertEqual(condition["severity"], "critical")
        self.assertIn("'db'", condition["message"])
        self.assertEqual(status["data"]["failed_checks"], 1)
        self.assertEqual(status["data"]["checks_total"], 2)
        self.assertEqual(status["data"]["response_latency_ms"], 1.5)

    def test_stale_result_fails_closed(self):
        stale = {"name": "api", "kind": "http_get", "ok": True, "status": 200,
                 "latency_ms": 1.0, "error": None, "checked_at": "2025-12-31T23:00:00+00:00"}
        failing = {"name": "db", "kind": "tcp", "ok": False, "status": None,
                   "latency_ms": None, "error": "x", "checked_at": self.NOW}
        status = probe.normalize(self._probes(), [stale, failing], now=self.NOW)
        self.assertEqual([condition["type"] for condition in status["conditions"]], ["probe_failed"])
        self.assertIn("'api'", status["conditions"][0]["message"])
        self.assertIn("'db'", status["conditions"][0]["message"])
        self.assertIn("stale", next(x["error"] for x in status["data"]["checks"] if x["name"] == "api"))


class CollectorTest(unittest.TestCase):
    def test_collects_due_checks_and_merges_into_state(self):
        state = PiNOCState()
        state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                                   online=True, address="pi.local", collection_method="local",
                                   integrations={})], replace=True)
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi", address="pi.local",
                              collection_method="local",
                              integrations={"probe": {"enabled": True, "checks": [
                                  valid_http_check(interval_seconds=60),
                                  valid_tcp_check(name="db", interval_seconds=60)]}})
        calls = []

        def runner(check, **kwargs):
            calls.append(check["name"])
            return {"name": check["name"], "kind": check["kind"], "ok": True, "status": 200,
                    "latency_ms": 3.0, "error": None, "checked_at": utcnow()}

        collector = ProbeCollector(state, lambda: [device], runner=runner,
                                   clock=lambda: 1000.0)
        collector.collect()
        self.assertEqual(calls, ["api", "db"])
        integrations = state.device("pi")["integrations"]
        self.assertEqual(integrations["probe"]["health"], "healthy")
        self.assertEqual(state.device("pi")["applications"]["probe"]["data"]["checks_total"], 2)
        # A second run before the interval elapses must not re-run checks.
        collector.collect()
        self.assertEqual(calls, ["api", "db"])
        # After the interval, checks re-run.
        collector.clock = lambda: 1000.0 + 61
        collector.collect()
        self.assertEqual(len(calls), 4)

    def test_disabled_probe_is_ignored(self):
        state = PiNOCState()
        state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                                   online=True, collection_method="local")], replace=True)
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi",
                              address="pi.local", collection_method="local",
                              integrations={"probe": {"enabled": False, "checks": [
                                  valid_http_check()]}})
        collector = ProbeCollector(state, lambda: [device],
                                   runner=lambda check, **kwargs: self.fail("must not run"))
        collector.collect()
        self.assertNotIn("probe", state.device("pi")["integrations"])

    def test_runner_exception_is_isolated(self):
        state = PiNOCState()
        state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                                   online=True, collection_method="local")], replace=True)
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi",
                              address="pi.local", collection_method="local",
                              integrations={"probe": {"checks": [valid_http_check()]}})

        def broken(check, **kwargs):
            raise RuntimeError("exploded")

        collector = ProbeCollector(state, lambda: [device], runner=broken,
                                   clock=lambda: 1.0)
        collector.collect()
        probe_status = state.device("pi")["integrations"]["probe"]
        self.assertEqual(probe_status["health"], "warning")
        self.assertIn("runner error", probe_status["data"]["checks"][0]["error"])


class FleetPlaceholderTest(unittest.TestCase):
    SCRIPT_OUTPUT = """__OS__;PRETTY_NAME="Raspberry Pi OS"
__UNAME__;Linux 6.6 armv7l
__MODEL__;Raspberry Pi 5
__UPTIME__;1000 2000
__LOAD__;1.0 1.0 1.0
__CPU__;cpu 10 0 10 80 0 0 0 0 0 0
__FREQ__;
__TEMP__;/sys/class/thermal/thermal_zone0/temp=50000
__THROTTLED__;throttled=0x0
__MEM__;MemTotal: 8000000 kB
MemAvailable: 4000000 kB
SwapTotal: 0 kB
SwapFree: 0 kB
__DF__;Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/root ext4 100000 50000 50000 50% /
__MOUNTS__/dev/root / ext4 rw 0 0
__ROUTE__;
__ADDR__;
__NET__;Inter-|   Receive
iface |bytes
eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0 0
__IW__;
__SERVICES__;
__UNITS__;ssh.service enabled
"""

    def test_probe_placeholder_is_seeded(self):
        device = DeviceConfig(id="pi", hostname="pi", friendly_name="Pi",
                              address="192.168.1.10", collection_method="ssh",
                              integrations={"probe": {"enabled": True, "checks": [
                                  valid_http_check()]}})

        def runner(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, self.SCRIPT_OUTPUT, "")

        collector = FleetCollector([device], runner=runner, timeout=1)
        snapshot = collector.collect_device(device)
        self.assertTrue(snapshot.online)
        probe_status = snapshot.integrations["probe"]
        self.assertEqual(probe_status["available"], True)
        self.assertEqual(probe_status["data_source"], "probe")
        self.assertEqual(probe_status["data"]["checks_total"], 1)
        self.assertNotIn("adsb", snapshot.integrations)


class WebSurfacingTest(unittest.TestCase):
    def test_probe_status_reaches_the_api(self):
        from pinoc.web import create_app

        state = PiNOCState()
        state.publish([DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                                   online=True, collection_method="local")], replace=True)
        status = probe.normalize(
            {"checks": [valid_http_check()]},
            [{"name": "api", "kind": "http_get", "ok": True, "status": 200,
              "latency_ms": 5.0, "error": None, "checked_at": "2026-01-01T00:00:00+00:00"}],
            now="2026-01-01T00:00:00+00:00")
        state.set_integration("pi", "probe", status)
        client = create_app(state, {"TESTING": True}).test_client()
        response = client.get("/api/devices/pi/integrations/probe")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["health"], "healthy")
        self.assertEqual(payload["data"]["checks"][0]["name"], "api")
        listing = client.get("/api/integrations").get_json()["integrations"]
        self.assertTrue(any(row["name"] == "probe" for row in listing))

    def test_probe_conditions_drive_alert_lifecycle(self):
        from pinoc.history import HistoryManager
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as folder:
            db = Database(f"{folder}/db.sqlite")
            self.assertTrue(db.initialize())
            history = HistoryManager(db, {})
            device = {"id": "pi", "online": True, "last_seen": "2026-01-01T00:00:00+00:00",
                      "cpu": {}, "memory": {}, "hardware": {}, "storage": [], "services": [],
                      "integrations": {
                          "probe": {"enabled": True, "health": "critical",
                                    "conditions": [{"type": "probe_failed",
                                                    "severity": "critical",
                                                    "message": "1 probe check(s) failing: 'api'"}]}}}
            history._alerts(device, "2026-01-01T00:00:00+00:00")
            rows = db.rows("SELECT * FROM alerts")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["alert_type"], "probe_failed")
            self.assertEqual(rows[0]["severity"], "critical")
            self.assertIn("api", rows[0]["message"])
            # Recovery resolves the same fingerprint.
            history._alerts({**device, "integrations": {"probe": {"enabled": True,
                          "health": "healthy", "conditions": []}}},
                            "2026-01-01T00:01:00+00:00")
            self.assertEqual(db.scalar("SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"), 0)


if __name__ == "__main__":
    unittest.main()
