"""Coverage for security-surface monitoring: auth failures, listening-port
inventory, and the tls_cert certificate-expiry probe kind."""
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from pinoc.collectors.fleet import (
    FleetCollector, parse_auth_failures, parse_listeners,
)
from pinoc.database import Database
from pinoc.device_config import DeviceConfig, DeviceConfigError, parse_device
from pinoc.history import HistoryManager
from pinoc.integrations import probe
from pinoc.models import DeviceState
from pinoc.state import PiNOCState

UTC = timezone.utc

BASE_SECTIONS = """__OS__
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
__LISTENTCP__
{tcp}
__LISTENUDP__
{udp}
__AUTHFAIL__
{authfail}
__SERVICES__
__UNITS__
"""


def device_config(**overrides) -> DeviceConfig:
    values = dict(id="pi", hostname="pi", friendly_name="Pi",
                  address="192.168.1.10", collection_method="ssh")
    values.update(overrides)
    return DeviceConfig(**values)


def completed(stdout: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.CompletedProcess(["sh"], 0, stdout, "")


def transcript(tcp="", udp="", authfail="") -> str:
    return BASE_SECTIONS.format(tcp=tcp, udp=udp, authfail=authfail)


SSHD_TCP = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100,fd=3))'
HTTP_TCP = 'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=200,fd=4))'
DNS_UDP = 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=300,fd=5))'


class ParseListenersTest(unittest.TestCase):
    def test_parses_proto_port_and_process(self):
        listeners = parse_listeners(SSHD_TCP, DNS_UDP)
        self.assertEqual(listeners, [
            {"proto": "tcp", "port": 22, "process": "sshd"},
            {"proto": "udp", "port": 53, "process": "dnsmasq"},
        ])

    def test_missing_process_name_is_none(self):
        listeners = parse_listeners("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", "")
        self.assertEqual(listeners, [{"proto": "tcp", "port": 22, "process": None}])

    def test_ipv6_and_wildcard_addresses(self):
        listeners = parse_listeners("LISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 128 *:80 *:*", "")
        self.assertEqual([x["port"] for x in listeners], [22, 80])

    def test_deduplicates_and_is_bounded(self):
        lines = "\n".join(f"LISTEN 0 128 0.0.0.0:{1000+i} 0.0.0.0:*" for i in range(300))
        listeners = parse_listeners(lines, "")
        self.assertEqual(len(listeners), 200)

    def test_garbage_lines_are_skipped(self):
        self.assertEqual(parse_listeners("not a real line", "also nonsense here"), [])


class ParseAuthFailuresTest(unittest.TestCase):
    def test_parses_count(self):
        self.assertEqual(parse_auth_failures("3\n"), 3)
        self.assertEqual(parse_auth_failures("0"), 0)

    def test_empty_or_unparseable_is_none(self):
        self.assertIsNone(parse_auth_failures(""))
        self.assertIsNone(parse_auth_failures("not a number"))


class DeviceConfigExpectedListenersTest(unittest.TestCase):
    def test_accepts_valid_entries_and_dedupes(self):
        device = parse_device({"hostname": "pi",
                               "expected_listeners": ["tcp:22", "TCP:22", "udp:53"]}, 0)
        self.assertEqual(device.expected_listeners, ("tcp:22", "udp:53"))

    def test_defaults_to_empty(self):
        self.assertEqual(parse_device({"hostname": "pi"}, 0).expected_listeners, ())

    def test_rejects_bad_entries(self):
        for bad in (["ftp:21"], ["tcp:0"], ["tcp:99999"], ["tcp"], [123]):
            with self.subTest(bad=bad):
                with self.assertRaises(DeviceConfigError):
                    parse_device({"hostname": "pi", "expected_listeners": bad}, 0)

    def test_rejects_too_many(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi",
                          "expected_listeners": [f"tcp:{1000+i}" for i in range(101)]}, 0)


class SecurityStatusIntegrationTest(unittest.TestCase):
    """End-to-end through FleetCollector.collect_device(): the "security"
    integration status it publishes, and the auth_fail/listener_change
    conditions' hysteresis/debounce across repeated polls."""

    def _collector(self, device, **kwargs):
        return FleetCollector([device], runner=self.runner, timeout=1,
                              log_tail_seconds=300, log_tail_lines=10, **kwargs)

    def setUp(self):
        self.stdout = transcript()

        def runner(args, **kwargs):
            return completed(self.stdout)
        self.runner = runner

    def test_no_signal_is_healthy_with_no_conditions(self):
        device = device_config()
        collector = self._collector(device)
        result = collector.collect_device(device)
        security = result.integrations["security"]
        self.assertEqual(security["health"], "healthy")
        self.assertEqual(security.get("conditions"), [])
        self.assertEqual(security["data"]["listeners"],
                         [])

    def test_auth_fail_opens_at_threshold_and_needs_hysteresis_to_close(self):
        device = device_config()
        collector = self._collector(device, auth_fail_warning=5, auth_fail_critical=20,
                                    auth_fail_hysteresis=2)

        def poll(count):
            # Force the low-frequency __authcheck__ cadence due every call,
            # exactly like test_service_logs.py's own cadence tests do.
            collector._last_jlogs[device.id] = __import__("time").monotonic() - 301
            self.stdout = transcript(authfail=str(count))
            return collector.collect_device(device)

        # Below threshold: no condition.
        result = poll(3)
        self.assertEqual(result.integrations["security"].get("conditions"), [])

        # At/above threshold: opens as a warning.
        result = poll(5)
        conditions = result.integrations["security"]["conditions"]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]["type"], "auth_fail")
        self.assertEqual(conditions[0]["severity"], "warning")

        # Above the critical threshold: escalates severity, stays one alert type.
        result = poll(25)
        conditions = result.integrations["security"]["conditions"]
        self.assertEqual(conditions[0]["severity"], "critical")

        # Drops just under warning but still above (warning - hysteresis):
        # hysteresis keeps it open rather than instantly closing.
        result = poll(4)
        conditions = result.integrations["security"]["conditions"]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]["severity"], "warning")

        # Drops below (warning - hysteresis): now it closes.
        result = poll(2)
        self.assertEqual(result.integrations["security"].get("conditions"), [])

    def test_auth_fail_not_due_every_poll_keeps_last_count(self):
        # __authcheck__ only runs on the jlogs cadence -- a poll where it
        # isn't due must not silently read as zero/healthy.
        device = device_config()
        collector = self._collector(device, auth_fail_warning=5)
        self.stdout = transcript(authfail="9")
        collector.collect_device(device)
        collector._last_jlogs[device.id] = __import__("time").monotonic()  # not due next cycle
        self.stdout = transcript(authfail="")  # authcheck_due=0 branch: nothing printed
        result = collector.collect_device(device)
        conditions = result.integrations["security"]["conditions"]
        self.assertEqual(conditions[0]["type"], "auth_fail")
        self.assertEqual(result.integrations["security"]["data"]["auth_failures"], 9)

    def test_listener_change_requires_configured_baseline(self):
        # No expected_listeners configured: an observed port is never flagged.
        device = device_config()
        collector = self._collector(device, listener_change_duration_seconds=0)
        self.stdout = transcript(tcp=HTTP_TCP)
        result = collector.collect_device(device)
        self.assertEqual(result.integrations["security"].get("conditions"), [])

    def test_unexpected_listener_opens_after_debounce(self):
        device = device_config(expected_listeners=("tcp:22",))
        collector = self._collector(device, listener_change_duration_seconds=30)
        self.stdout = transcript(tcp=f"{SSHD_TCP}\n{HTTP_TCP}")
        with patch("pinoc.collectors.fleet.time.monotonic", return_value=1000.0):
            result = collector.collect_device(device)
        # First observation: not yet sustained long enough -- no alert yet
        # (rate-limits a single flappy poll).
        self.assertEqual(result.integrations["security"].get("conditions"), [])
        with patch("pinoc.collectors.fleet.time.monotonic", return_value=1035.0):
            result = collector.collect_device(device)
        conditions = result.integrations["security"]["conditions"]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]["type"], "listener_change")
        self.assertIn("8080", conditions[0]["message"])
        self.assertEqual(result.integrations["security"]["data"]["unexpected_listeners"], ["tcp:8080"])

    def test_missing_expected_listener_opens_after_debounce(self):
        device = device_config(expected_listeners=("tcp:22", "udp:53"))
        collector = self._collector(device, listener_change_duration_seconds=10)
        self.stdout = transcript(tcp=SSHD_TCP)  # udp:53 never observed
        with patch("pinoc.collectors.fleet.time.monotonic", return_value=0.0):
            collector.collect_device(device)
        with patch("pinoc.collectors.fleet.time.monotonic", return_value=11.0):
            result = collector.collect_device(device)
        conditions = result.integrations["security"]["conditions"]
        self.assertEqual(conditions[0]["type"], "listener_change")
        self.assertEqual(result.integrations["security"]["data"]["missing_listeners"], ["udp:53"])

    def test_listener_reverting_before_debounce_never_alerts(self):
        device = device_config(expected_listeners=("tcp:22",))
        collector = self._collector(device, listener_change_duration_seconds=60)
        with patch("pinoc.collectors.fleet.time.monotonic", return_value=0.0):
            self.stdout = transcript(tcp=f"{SSHD_TCP}\n{HTTP_TCP}")
            collector.collect_device(device)
        with patch("pinoc.collectors.fleet.time.monotonic", return_value=5.0):
            self.stdout = transcript(tcp=SSHD_TCP)  # flaps back before the debounce window
            result = collector.collect_device(device)
        self.assertEqual(result.integrations["security"].get("conditions"), [])


class HistoryAlertLifecycleTest(unittest.TestCase):
    """The generic integration-conditions pickup in
    HistoryManager._alerts() (the same path probe_failed/raid_degraded
    already use) drives auth_fail/listener_change/cert_expiry through the
    normal open -> mute/ack -> resolve lifecycle with no special-casing."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db = Database(f"{self._tmpdir.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.history = HistoryManager(self.db, {}, state=self.state)

    def device(self, conditions):
        return {"id": "pi", "hostname": "pi", "friendly_name": "Pi", "online": True,
               "cpu": {}, "memory": {}, "hardware": {}, "storage": [], "media": [],
               "services": [], "important_paths": [],
               "integrations": {"security": {"enabled": True, "conditions": conditions}}}

    def stamp(self, seconds=0):
        return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()

    def test_condition_opens_mutes_acks_and_resolves(self):
        auth_condition = [{"type": "auth_fail", "severity": "warning",
                           "message": "5 failed SSH login attempt(s)"}]
        opened, resolved = self.history._alerts(self.device(auth_condition), self.stamp(0))
        self.assertEqual(len(opened), 1)
        alert = opened[0]
        self.assertEqual(alert["alert_type"], "auth_fail")
        self.assertEqual(alert["device_id"], "pi")

        row = self.db.rows("SELECT * FROM alerts WHERE alert_id=?", (alert["alert_id"],))[0]
        self.assertEqual(row["state"], "active")

        self.history.acknowledge(alert["alert_id"])
        row = self.db.rows("SELECT * FROM alerts WHERE alert_id=?", (alert["alert_id"],))[0]
        self.assertEqual(row["state"], "acknowledged")
        self.assertIsNotNone(row["acknowledged_at"])

        until = self.stamp(3600)
        self.history.mute(alert["alert_id"], until)
        row = self.db.rows("SELECT * FROM alerts WHERE alert_id=?", (alert["alert_id"],))[0]
        self.assertEqual(row["state"], "muted")

        # Condition still active on the next poll: stays open (same
        # fingerprint), does not spam a second insert/notification.
        opened_again, _ = self.history._alerts(self.device(auth_condition), self.stamp(10))
        self.assertEqual(opened_again, [])

        # Condition clears: alert resolves.
        _, resolved = self.history._alerts(self.device([]), self.stamp(20))
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["alert_type"], "auth_fail")
        row = self.db.rows("SELECT * FROM alerts WHERE alert_id=?", (alert["alert_id"],))[0]
        self.assertIsNotNone(row["resolved_at"])

    def test_listener_change_and_cert_expiry_types_reach_the_alert_table(self):
        conditions = [
            {"type": "listener_change", "severity": "warning", "message": "unexpected listener tcp:8080"},
            {"type": "cert_expiry", "severity": "critical", "message": "cert expires in 0.5 day(s)"},
        ]
        opened, _ = self.history._alerts(self.device(conditions), self.stamp(0))
        types = sorted(a["alert_type"] for a in opened)
        self.assertEqual(types, ["cert_expiry", "listener_change"])
        severities = {a["alert_type"]: a["severity"] for a in opened}
        self.assertEqual(severities["cert_expiry"], "critical")
        self.assertEqual(severities["listener_change"], "warning")


class ProbeTlsCertValidationTest(unittest.TestCase):
    def test_accepts_valid_tls_cert_check(self):
        check = probe.validate_check({"name": "web-cert", "kind": "tls_cert",
                                      "host": "example.internal", "port": 443})
        self.assertEqual((check["kind"], check["host"], check["port"]), ("tls_cert", "example.internal", 443))

    def test_requires_host_and_port(self):
        with self.assertRaises(probe.ProbeConfigError):
            probe.validate_check({"name": "x", "kind": "tls_cert", "port": 443})
        with self.assertRaises(probe.ProbeConfigError):
            probe.validate_check({"name": "x", "kind": "tls_cert", "host": "h"})


def cert_expiring_in(days: float):
    expires = datetime.now(UTC) + timedelta(days=days)
    return {"notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT")}


class ProbeTlsCertRunCheckTest(unittest.TestCase):
    def _check(self, **overrides):
        check = {"name": "web-cert", "kind": "tls_cert", "host": "h", "port": 443,
                 "timeout_seconds": 5, "interval_seconds": 60}
        check.update(overrides)
        return probe.validate_check(check)

    def test_far_future_expiry_is_ok(self):
        result = probe.run_check(self._check(),
                                 cert_fetcher=lambda h, p, t: cert_expiring_in(120),
                                 now="2026-01-01T00:00:00+00:00")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertGreater(result["days_remaining"], 100)

    def test_near_expiry_is_not_ok_but_still_parses_days_remaining(self):
        result = probe.run_check(self._check(),
                                 cert_fetcher=lambda h, p, t: cert_expiring_in(5),
                                 now="2026-01-01T00:00:00+00:00")
        self.assertFalse(result["ok"])
        self.assertLess(result["days_remaining"], 7)
        self.assertIn("expires in", result["error"])

    def test_handshake_failure_is_reported(self):
        def boom(host, port, timeout):
            raise OSError("connection refused")
        result = probe.run_check(self._check(), cert_fetcher=boom, now="2026-01-01T00:00:00+00:00")
        self.assertFalse(result["ok"])
        self.assertIn("certificate check", result["error"])


class ProbeTlsCertLadderTest(unittest.TestCase):
    NOW = "2026-01-01T00:00:00+00:00"

    def _probes(self, **check_overrides):
        check = {"name": "web-cert", "kind": "tls_cert", "host": "h", "port": 443,
                 "timeout_seconds": 5, "interval_seconds": 60}
        check.update(check_overrides)
        return {"checks": [probe.validate_check(check)]}

    def _result(self, days):
        return {"name": "web-cert", "kind": "tls_cert", "ok": days > probe.CERT_NOTICE_DAYS,
                "status": "valid", "days_remaining": days,
                "expires_at": self.NOW, "error": None, "checked_at": self.NOW}

    def test_no_alert_well_before_expiry(self):
        status = probe.normalize(self._probes(), [self._result(60)], now=self.NOW)
        self.assertEqual(status["conditions"], [])
        self.assertEqual(status["health"], "healthy")

    def test_notice_band_is_info_severity(self):
        status = probe.normalize(self._probes(), [self._result(20)], now=self.NOW)
        [condition] = status["conditions"]
        self.assertEqual(condition["type"], "cert_expiry")
        self.assertEqual(condition["severity"], "info")

    def test_warning_band(self):
        status = probe.normalize(self._probes(), [self._result(5)], now=self.NOW)
        [condition] = status["conditions"]
        self.assertEqual(condition["severity"], "warning")

    def test_critical_band_at_one_day(self):
        status = probe.normalize(self._probes(), [self._result(0.5)], now=self.NOW)
        [condition] = status["conditions"]
        self.assertEqual(condition["severity"], "critical")
        self.assertEqual(status["health"], "critical")

    def test_cert_check_does_not_pollute_generic_probe_failed(self):
        # A failing tls_cert check must not also show up in the generic
        # probe_failed bucket -- it has its own dedicated alert type.
        status = probe.normalize(self._probes(), [self._result(0.2)], now=self.NOW)
        types = [c["type"] for c in status["conditions"]]
        self.assertEqual(types, ["cert_expiry"])
        self.assertEqual(status["data"]["failed_checks"], 1)

    def test_mixed_cert_and_http_failures_open_two_distinct_conditions(self):
        http_check = probe.validate_check({"name": "api", "kind": "http_get",
                                           "url": "http://h/", "timeout_seconds": 5})
        probes = {"checks": [self._probes()["checks"][0], http_check]}
        http_result = {"name": "api", "kind": "http_get", "ok": False, "status": 500,
                       "error": "unexpected status 500", "latency_ms": 1.0, "checked_at": self.NOW}
        status = probe.normalize(probes, [self._result(0.5), http_result], now=self.NOW)
        types = sorted(c["type"] for c in status["conditions"])
        self.assertEqual(types, ["cert_expiry", "probe_failed"])


if __name__ == "__main__":
    unittest.main()
