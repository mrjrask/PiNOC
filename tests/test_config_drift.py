"""Coverage for configuration drift detection and repair (enhancement #6):
expected-state config validation, actual-state parsing from fake SSH
output, diff computation, the config_drift alert lifecycle, and the two
allowlisted repair actions through the real ActionDispatcher."""
import base64
import hashlib
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.actions import ActionDispatcher, ActionError
from pinoc.backup import load_config_snapshot, save_config_snapshot
from pinoc.collectors.fleet import (
    FleetCollector, compute_config_drift, format_drift_diff, parse_drift_files,
    parse_sshd_options,
)
from pinoc.database import Database
from pinoc.device_config import ConfigDriftSpec, DeviceConfig, DeviceConfigError, parse_device
from pinoc.history import HistoryManager
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
__LISTENUDP__
__AUTHFAIL__
__SERVICES__
Id=ssh.service
LoadState=loaded
ActiveState=active
SubState=running
MainPID=100
ActiveEnterTimestampMonotonic=0
NRestarts=0
MemoryCurrent=1000
UnitFileState={unit_file_state}

__UNITS__
__DRIFTFILES__
{driftfiles}
__SSHD__
{sshd}
"""


def device_config(**overrides) -> DeviceConfig:
    values = dict(id="pi", hostname="pi", friendly_name="Pi",
                 address="192.168.1.10", collection_method="ssh")
    values.update(overrides)
    return DeviceConfig(**values)


def file_record(path: str, content: bytes) -> str:
    return f"=== {path}\nSIZE:{len(content)}\n{base64.b64encode(content).decode()}"


def missing_record(path: str) -> str:
    return f"=== {path}\nMISSING\n-"


def transcript(unit_file_state="enabled", driftfiles="", sshd="") -> str:
    return BASE_SECTIONS.format(unit_file_state=unit_file_state, driftfiles=driftfiles, sshd=sshd)


def completed(stdout: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.CompletedProcess(["sh"], 0, stdout, "")


SSHD_GOOD_CONTENT = b"PermitRootLogin no\n"
SSHD_GOOD_SHA = hashlib.sha256(SSHD_GOOD_CONTENT).hexdigest()


class DeviceConfigDriftValidationTest(unittest.TestCase):
    def test_accepts_a_full_spec(self):
        device = parse_device({"hostname": "pi", "config_drift": {
            "expected_units": ["ssh.service", "ssh.service"],
            "expected_files": {"/etc/ssh/sshd_config": SSHD_GOOD_SHA.upper()},
            "expected_sshd_options": {"PermitRootLogin": "no"},
        }}, 0)
        self.assertEqual(device.config_drift.expected_units, ("ssh.service",))
        self.assertEqual(device.config_drift.expected_files, {"/etc/ssh/sshd_config": SSHD_GOOD_SHA})
        self.assertEqual(device.config_drift.expected_sshd_options, {"permitrootlogin": "no"})

    def test_defaults_to_empty(self):
        device = parse_device({"hostname": "pi"}, 0)
        self.assertTrue(device.config_drift.is_empty())
        self.assertEqual(device.config_drift, ConfigDriftSpec())

    def test_rejects_bad_unit_names(self):
        for bad in ["not a unit", "ssh.socket", "../ssh.service", "x" * 130 + ".service"]:
            with self.subTest(bad=bad):
                with self.assertRaises(DeviceConfigError):
                    parse_device({"hostname": "pi", "config_drift": {"expected_units": [bad]}}, 0)

    def test_rejects_too_many_units(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_units": [f"u{i}.service" for i in range(21)]}}, 0)

    def test_rejects_bad_file_paths_and_hashes(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_files": {"relative/path": SSHD_GOOD_SHA}}}, 0)
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_files": {"/etc/foo": "not-a-sha256"}}}, 0)
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_files": {"/etc/../etc/foo": SSHD_GOOD_SHA}}}, 0)

    def test_rejects_too_many_files(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_files": {f"/etc/f{i}": SSHD_GOOD_SHA for i in range(11)}}}, 0)

    def test_rejects_bad_sshd_options(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_sshd_options": {"bad option!": "no"}}}, 0)
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_sshd_options": {"PermitRootLogin": "no\nEvil x"}}}, 0)
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_sshd_options": {"PermitRootLogin": ""}}}, 0)

    def test_rejects_too_many_sshd_options(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": {
                "expected_sshd_options": {f"Option{i}": "x" for i in range(26)}}}, 0)

    def test_rejects_non_object(self):
        with self.assertRaises(DeviceConfigError):
            parse_device({"hostname": "pi", "config_drift": "nope"}, 0)

    def test_allowlisted_actions_accept_config_drift_ids(self):
        device = parse_device({"hostname": "pi", "allowed_actions": [
            "config_drift.reenable_unit", "config_drift.restore_file"]}, 0)
        self.assertEqual(set(device.allowed_actions),
                         {"config_drift.reenable_unit", "config_drift.restore_file"})


class ParseDriftFilesTest(unittest.TestCase):
    def test_parses_matching_content_and_hash(self):
        content = b"hello world\n"
        result = parse_drift_files(file_record("/etc/x.conf", content))
        entry = result["/etc/x.conf"]
        self.assertTrue(entry["exists"])
        self.assertEqual(entry["size"], len(content))
        self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(entry["content"], content)

    def test_missing_file(self):
        result = parse_drift_files(missing_record("/etc/gone.conf"))
        self.assertEqual(result["/etc/gone.conf"],
                         {"exists": False, "size": None, "sha256": None, "content": None})

    def test_oversized_file_is_unverifiable(self):
        text = "=== /etc/big.conf\nSIZE:999999\n-"
        entry = parse_drift_files(text)["/etc/big.conf"]
        self.assertTrue(entry["exists"])
        self.assertEqual(entry["size"], 999999)
        self.assertIsNone(entry["sha256"])
        self.assertIsNone(entry["content"])

    def test_multiple_records(self):
        text = "\n".join([file_record("/a", b"one"), file_record("/b", b"two")])
        result = parse_drift_files(text)
        self.assertEqual(set(result), {"/a", "/b"})
        self.assertEqual(result["/a"]["content"], b"one")
        self.assertEqual(result["/b"]["content"], b"two")

    def test_garbage_is_ignored(self):
        self.assertEqual(parse_drift_files("not a real section"), {})


class ParseSshdOptionsTest(unittest.TestCase):
    def test_parses_key_value_lines(self):
        text = "permitrootlogin no\npasswordauthentication no\nport 22"
        self.assertEqual(parse_sshd_options(text),
                         {"permitrootlogin": "no", "passwordauthentication": "no", "port": "22"})

    def test_uppercase_keys_are_lowercased(self):
        self.assertEqual(parse_sshd_options("PermitRootLogin no")["permitrootlogin"], "no")

    def test_blank_and_malformed_lines_are_skipped(self):
        self.assertEqual(parse_sshd_options("\n   \nsolo-token\n"), {})


class ComputeConfigDriftTest(unittest.TestCase):
    def _spec(self, **overrides):
        values = dict(expected_units=("ssh.service",),
                     expected_files={"/etc/ssh/sshd_config": SSHD_GOOD_SHA},
                     expected_sshd_options={"permitrootlogin": "no"})
        values.update(overrides)
        return ConfigDriftSpec(**values)

    def test_no_drift_when_everything_matches(self):
        spec = self._spec()
        unit_states = {"ssh.service": {"unit_file_state": "enabled"}}
        drift_files = {"/etc/ssh/sshd_config": {"exists": True, "size": len(SSHD_GOOD_CONTENT),
                                                "sha256": SSHD_GOOD_SHA, "content": SSHD_GOOD_CONTENT}}
        sshd_options = {"permitrootlogin": "no"}
        drift, snapshots = compute_config_drift(spec, unit_states, drift_files, sshd_options,
                                                 files_due=True, sshd_due=True)
        self.assertEqual(drift, [])
        self.assertEqual(snapshots, [{"path": "/etc/ssh/sshd_config", "sha256": SSHD_GOOD_SHA,
                                      "content": SSHD_GOOD_CONTENT}])

    def test_disabled_and_masked_units_drift(self):
        spec = self._spec(expected_files={}, expected_sshd_options={})
        for state in ("disabled", "masked", "linked", "bad"):
            with self.subTest(state=state):
                drift, _ = compute_config_drift(
                    spec, {"ssh.service": {"unit_file_state": state}}, {}, {},
                    files_due=False, sshd_due=False)
                self.assertEqual(drift, [{"type": "unit", "name": "ssh.service",
                                          "expected": "enabled", "actual": state}])

    def test_static_and_indirect_units_are_not_drift(self):
        spec = self._spec(expected_files={}, expected_sshd_options={})
        for state in ("static", "enabled-runtime", "alias", "indirect"):
            drift, _ = compute_config_drift(
                spec, {"ssh.service": {"unit_file_state": state}}, {}, {},
                files_due=False, sshd_due=False)
            self.assertEqual(drift, [])

    def test_unit_never_reported_is_not_found(self):
        spec = self._spec(expected_files={}, expected_sshd_options={})
        drift, _ = compute_config_drift(spec, {}, {}, {}, files_due=False, sshd_due=False)
        self.assertEqual(drift, [{"type": "unit", "name": "ssh.service",
                                  "expected": "enabled", "actual": "unit not found"}])

    def test_missing_file_drifts(self):
        spec = self._spec(expected_units=(), expected_sshd_options={})
        drift_files = {"/etc/ssh/sshd_config": {"exists": False, "size": None, "sha256": None, "content": None}}
        drift, snapshots = compute_config_drift(spec, {}, drift_files, {}, files_due=True, sshd_due=False)
        self.assertEqual(drift, [{"type": "file", "name": "/etc/ssh/sshd_config",
                                  "expected": SSHD_GOOD_SHA[:12], "actual": "missing"}])
        self.assertEqual(snapshots, [])

    def test_wrong_hash_file_drifts(self):
        spec = self._spec(expected_units=(), expected_sshd_options={})
        bad = b"PermitRootLogin yes\n"
        bad_hash = hashlib.sha256(bad).hexdigest()
        drift_files = {"/etc/ssh/sshd_config": {"exists": True, "size": len(bad), "sha256": bad_hash, "content": bad}}
        drift, snapshots = compute_config_drift(spec, {}, drift_files, {}, files_due=True, sshd_due=False)
        self.assertEqual(drift, [{"type": "file", "name": "/etc/ssh/sshd_config",
                                  "expected": SSHD_GOOD_SHA[:12], "actual": bad_hash[:12]}])
        self.assertEqual(snapshots, [])

    def test_sshd_option_mismatch_drifts(self):
        spec = self._spec(expected_units=(), expected_files={})
        drift, _ = compute_config_drift(spec, {}, {}, {"permitrootlogin": "yes"},
                                        files_due=False, sshd_due=True)
        self.assertEqual(drift, [{"type": "sshd_option", "name": "permitrootlogin",
                                  "expected": "no", "actual": "yes"}])

    def test_not_due_carries_forward_previous_file_and_sshd_items(self):
        spec = self._spec(expected_units=())
        previous = [{"type": "file", "name": "/etc/ssh/sshd_config", "expected": "aaa", "actual": "bbb"},
                   {"type": "sshd_option", "name": "permitrootlogin", "expected": "no", "actual": "yes"}]
        drift, snapshots = compute_config_drift(spec, {}, {}, {}, files_due=False, sshd_due=False,
                                                 previous=previous)
        self.assertEqual(drift, previous)
        self.assertEqual(snapshots, [])

    def test_format_drift_diff_is_readable(self):
        drift = [{"type": "unit", "name": "ssh.service", "expected": "enabled", "actual": "disabled"},
                {"type": "file", "name": "/etc/ssh/sshd_config", "expected": "abc", "actual": "def"},
                {"type": "sshd_option", "name": "permitrootlogin", "expected": "no", "actual": "yes"}]
        text = format_drift_diff(drift)
        self.assertEqual(text, (
            "unit ssh.service: expected 'enabled', found 'disabled'\n"
            "file /etc/ssh/sshd_config: expected 'abc', found 'def'\n"
            "sshd option permitrootlogin: expected 'no', found 'yes'"))


class FleetCollectorConfigDriftIntegrationTest(unittest.TestCase):
    """End-to-end through FleetCollector.collect_device()."""

    def _device(self, config_drift=None, **overrides):
        spec = config_drift if config_drift is not None else ConfigDriftSpec(
            expected_units=("ssh.service",),
            expected_files={"/etc/ssh/sshd_config": SSHD_GOOD_SHA},
            expected_sshd_options={"permitrootlogin": "no"})
        return device_config(config_drift=spec, **overrides)

    def _collector(self, device, **kwargs):
        return FleetCollector([device], runner=self.runner, timeout=1, drift_check_seconds=1, **kwargs)

    def setUp(self):
        self.stdout = transcript(
            driftfiles=file_record("/etc/ssh/sshd_config", SSHD_GOOD_CONTENT),
            sshd="permitrootlogin no")

        def runner(args, **kwargs):
            return completed(self.stdout)
        self.runner = runner

    def test_no_spec_means_no_integration_entry(self):
        device = device_config()
        collector = self._collector(device)
        result = collector.collect_device(device)
        self.assertNotIn("config_drift", result.integrations)
        self.assertEqual(result.config_drift_expected, {})

    def test_matching_state_is_healthy_and_captures_snapshot(self):
        device = self._device()
        collector = self._collector(device)
        result = collector.collect_device(device)
        status = result.integrations["config_drift"]
        self.assertEqual(status["health"], "healthy")
        self.assertEqual(status.get("conditions"), [])
        snapshots = status["data"]["good_snapshots"]
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["sha256"], SSHD_GOOD_SHA)
        self.assertEqual(base64.b64decode(snapshots[0]["content_b64"]), SSHD_GOOD_CONTENT)

    def test_drifted_state_opens_condition_with_readable_diff(self):
        device = self._device()
        self.stdout = transcript(
            unit_file_state="disabled",
            driftfiles=file_record("/etc/ssh/sshd_config", b"garbage"),
            sshd="permitrootlogin yes")
        collector = self._collector(device)
        result = collector.collect_device(device)
        status = result.integrations["config_drift"]
        self.assertEqual(status["health"], "warning")
        conditions = status["conditions"]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]["type"], "config_drift")
        message = conditions[0]["message"]
        self.assertIn("unit ssh.service: expected 'enabled', found 'disabled'", message)
        self.assertIn("sshd option permitrootlogin: expected 'no', found 'yes'", message)
        self.assertIn("file /etc/ssh/sshd_config", message)

    def test_expected_state_spec_is_carried_to_device_state(self):
        device = self._device()
        collector = self._collector(device)
        result = collector.collect_device(device)
        self.assertEqual(result.config_drift_expected["expected_units"], ["ssh.service"])
        self.assertEqual(result.config_drift_expected["expected_files"],
                         {"/etc/ssh/sshd_config": SSHD_GOOD_SHA})

    def test_file_and_sshd_checks_are_not_due_every_poll(self):
        # drift_check_seconds gates the expensive file/sshd checks; the unit
        # check still runs every poll (it rides along with __SERVICES__).
        device = self._device()
        collector = FleetCollector([device], runner=self.runner, timeout=1, drift_check_seconds=300)
        first = collector.collect_device(device)
        self.assertEqual(first.integrations["config_drift"]["data"]["drift"], [])
        # Second poll: drift check not due, but the file content changes on
        # the wire -- must not be picked up (and must not flap the alert).
        self.stdout = transcript(
            driftfiles=file_record("/etc/ssh/sshd_config", b"garbage"),
            sshd="permitrootlogin yes")
        second = collector.collect_device(device)
        self.assertEqual(second.integrations["config_drift"]["data"]["drift"], [])

    def test_unit_never_found_drifts(self):
        device = self._device(config_drift=ConfigDriftSpec(expected_units=("other.service",)))
        collector = self._collector(device)
        result = collector.collect_device(device)
        drift = result.integrations["config_drift"]["data"]["drift"]
        self.assertEqual(drift, [{"type": "unit", "name": "other.service",
                                  "expected": "enabled", "actual": "unit not found"}])


class HistoryAlertLifecycleTest(unittest.TestCase):
    """config_drift opens/resolves through the same generic
    integration-conditions path as security's auth_fail/listener_change --
    see HistoryManager._alerts()."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db = Database(f"{self._tmpdir.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.history = HistoryManager(self.db, {}, state=self.state)

    def device(self, conditions, good_snapshots=None):
        return {"id": "pi", "hostname": "pi", "friendly_name": "Pi", "online": True,
               "cpu": {}, "memory": {}, "hardware": {}, "storage": [], "media": [],
               "services": [], "important_paths": [],
               "integrations": {"config_drift": {"enabled": True, "conditions": conditions,
                                                  "data": {"good_snapshots": good_snapshots or []}}}}

    def stamp(self, seconds=0):
        return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()

    def test_drift_found_opens_then_resolves_once_matching_again(self):
        condition = [{"type": "config_drift", "severity": "warning",
                     "message": "unit ssh.service: expected 'enabled', found 'disabled'"}]
        opened, _ = self.history._alerts(self.device(condition), self.stamp(0))
        self.assertEqual(len(opened), 1)
        alert = opened[0]
        self.assertEqual(alert["alert_type"], "config_drift")
        self.assertEqual(alert["severity"], "warning")
        row = self.db.rows("SELECT * FROM alerts WHERE alert_id=?", (alert["alert_id"],))[0]
        self.assertEqual(row["state"], "active")
        self.assertIn("ssh.service", row["message"])

        # Still drifted on the next poll: same fingerprint, no duplicate.
        opened_again, _ = self.history._alerts(self.device(condition), self.stamp(10))
        self.assertEqual(opened_again, [])

        # Matches again: resolves.
        _, resolved = self.history._alerts(self.device([]), self.stamp(20))
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["alert_type"], "config_drift")
        row = self.db.rows("SELECT * FROM alerts WHERE alert_id=?", (alert["alert_id"],))[0]
        self.assertIsNotNone(row["resolved_at"])

    def test_config_drift_is_distinct_from_service_failure_alerts(self):
        device = self.device([{"type": "config_drift", "severity": "warning", "message": "m"}])
        device["services"] = [{"name": "ssh.service", "state": "failed", "critical": True}]
        device["critical_services"] = ["ssh.service"]
        opened, _ = self.history._alerts(device, self.stamp(0))
        types = sorted(a["alert_type"] for a in opened)
        self.assertEqual(types, ["config_drift", "critical_service_failed"])

    def test_persist_config_snapshots_writes_to_backup_store(self):
        content = SSHD_GOOD_CONTENT
        snapshots = [{"path": "/etc/ssh/sshd_config", "sha256": SSHD_GOOD_SHA,
                     "content_b64": base64.b64encode(content).decode()}]
        self.history._persist_config_snapshots(self.device([], snapshots))
        row = load_config_snapshot(self.db, "pi", "/etc/ssh/sshd_config")
        self.assertIsNotNone(row)
        self.assertEqual(row["sha256"], SSHD_GOOD_SHA)
        self.assertEqual(bytes(row["content"]), content)

    def test_persist_config_snapshots_ignores_missing_integration(self):
        # Must not raise when a device has no config_drift integration at all.
        self.history._persist_config_snapshots({"id": "pi", "integrations": {}})


class Coordinator:
    def refresh_device(self, d):
        pass

    def refresh(self):
        pass


def make_device(**overrides) -> DeviceState:
    values = dict(id="pi", hostname="pi", friendly_name="Pi", online=True, address="host",
                 collection_method="ssh", ssh_user="pi", ssh_port=22,
                 allowed_actions=["config_drift.reenable_unit", "config_drift.restore_file"],
                 config_drift_expected={"expected_units": ["ssh.service"],
                                       "expected_files": {"/etc/ssh/sshd_config": SSHD_GOOD_SHA},
                                       "expected_sshd_options": {"permitrootlogin": "no"}})
    values.update(overrides)
    return DeviceState(**values)


def wait_for(dispatcher, job, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        row = dispatcher.get(job["job_id"])
        if row["status"] not in ("queued", "running"):
            return row
        time.sleep(0.01)
    raise AssertionError("action job did not finish")


class RepairActionsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        self.assertTrue(self.db.initialize())
        self.state = PiNOCState()
        self.state.publish([make_device()], replace=True)

    def _dispatcher(self, runner=None):
        dispatcher = ActionDispatcher(self.db, self.state, Coordinator(),
                                      runner=runner or (lambda *a, **k: subprocess.CompletedProcess([], 0, "", "")))
        self.addCleanup(dispatcher.stop)
        return dispatcher

    # -- validation: bounded to the device's own expected-state spec --

    def test_reenable_unit_rejects_unit_outside_spec(self):
        dispatcher = self._dispatcher()
        with self.assertRaises(ActionError) as ctx:
            dispatcher.validate("config_drift.reenable_unit", "pi", "other.service")
        self.assertIn("expected-state spec", str(ctx.exception))

    def test_reenable_unit_accepts_unit_in_spec(self):
        dispatcher = self._dispatcher()
        dispatcher.validate("config_drift.reenable_unit", "pi", "ssh.service")

    def test_restore_file_rejects_path_outside_spec(self):
        dispatcher = self._dispatcher()
        with self.assertRaises(ActionError) as ctx:
            dispatcher.validate("config_drift.restore_file", "pi", "/etc/passwd")
        self.assertIn("expected-state spec", str(ctx.exception))

    def test_restore_file_accepts_path_in_spec(self):
        dispatcher = self._dispatcher()
        dispatcher.validate("config_drift.restore_file", "pi", "/etc/ssh/sshd_config")

    def test_actions_require_device_allowlisting(self):
        self.state.publish([make_device(allowed_actions=[])], replace=True)
        dispatcher = self._dispatcher()
        with self.assertRaises(ActionError) as ctx:
            dispatcher.validate("config_drift.reenable_unit", "pi", "ssh.service")
        self.assertIn("not approved", str(ctx.exception))
        with self.assertRaises(ActionError):
            dispatcher.validate("config_drift.restore_file", "pi", "/etc/ssh/sshd_config")

    def test_actions_are_in_allowlistable_actions(self):
        from pinoc.actions import ALLOWLISTABLE_ACTIONS
        self.assertIn("config_drift.reenable_unit", ALLOWLISTABLE_ACTIONS)
        self.assertIn("config_drift.restore_file", ALLOWLISTABLE_ACTIONS)

    # -- execution through the real dispatcher/queue/audit trail --

    def test_reenable_unit_unmasks_then_enables(self):
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        dispatcher = self._dispatcher(runner)
        job = dispatcher.enqueue("config_drift.reenable_unit", "pi", "ssh.service", "op", "operator")
        row = wait_for(dispatcher, job)
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("unmasked and enabled", row["summary"])
        tails = [args[-3:] for args in calls]
        self.assertIn(["systemctl", "unmask", "ssh.service"], tails)
        self.assertIn(["systemctl", "enable", "ssh.service"], tails)
        count = self.db.scalar("SELECT COUNT(*) FROM audit_records WHERE action='config_drift.reenable_unit'")
        self.assertGreaterEqual(count or 0, 1)

    def test_reenable_unit_reports_enable_failure(self):
        def runner(args, **kwargs):
            if "enable" in args:
                return subprocess.CompletedProcess(args, 1, "", "Unit not found.")
            return subprocess.CompletedProcess(args, 0, "", "")

        dispatcher = self._dispatcher(runner)
        job = dispatcher.enqueue("config_drift.reenable_unit", "pi", "ssh.service", "op", "operator")
        row = wait_for(dispatcher, job)
        self.assertEqual(row["status"], "failed")

    def test_restore_file_fails_without_a_known_good_snapshot(self):
        dispatcher = self._dispatcher()
        job = dispatcher.enqueue("config_drift.restore_file", "pi", "/etc/ssh/sshd_config", "op", "operator")
        row = wait_for(dispatcher, job)
        self.assertEqual(row["status"], "failed")
        self.assertIn("no known-good snapshot", row["error"])

    def test_restore_file_fails_when_snapshot_hash_no_longer_matches_spec(self):
        # A stale snapshot captured under a since-changed expected hash must
        # not be trusted for restore.
        save_config_snapshot(self.db, "pi", "/etc/ssh/sshd_config", "0" * 64, b"old content")
        dispatcher = self._dispatcher()
        job = dispatcher.enqueue("config_drift.restore_file", "pi", "/etc/ssh/sshd_config", "op", "operator")
        row = wait_for(dispatcher, job)
        self.assertEqual(row["status"], "failed")
        self.assertIn("no known-good snapshot", row["error"])

    def test_restore_file_writes_snapshot_content_via_tee(self):
        save_config_snapshot(self.db, "pi", "/etc/ssh/sshd_config", SSHD_GOOD_SHA, SSHD_GOOD_CONTENT)
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, "", "")

        dispatcher = self._dispatcher(runner)
        job = dispatcher.enqueue("config_drift.restore_file", "pi", "/etc/ssh/sshd_config", "op", "operator")
        row = wait_for(dispatcher, job)
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("restored", row["summary"])
        tee_calls = [(args, kwargs) for args, kwargs in calls if "tee" in args]
        self.assertEqual(len(tee_calls), 1)
        args, kwargs = tee_calls[0]
        self.assertIn("/etc/ssh/sshd_config", args)
        self.assertEqual(kwargs.get("input"), SSHD_GOOD_CONTENT.decode("utf-8"))
        for args, kwargs in calls:
            self.assertNotIn("shell", kwargs)

    def test_offline_device_rejected(self):
        self.state.publish([make_device(online=False, health="offline")], replace=True)
        dispatcher = self._dispatcher()
        with self.assertRaises(ActionError):
            dispatcher.validate("config_drift.reenable_unit", "pi", "ssh.service")


if __name__ == "__main__":
    unittest.main()
