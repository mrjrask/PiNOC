"""Coverage for the application model (PiNOC 2.0 Phase 1, P1-R02).

Eight layers:

* :class:`TestDatabaseSchema` -- migration 21 (applications, instances,
  health snapshots) and the schema-version invariant.
* :class:`TestStrategies` -- every registered health strategy against
  crafted device dicts (no threads): the conclusive/inconclusive split,
  the critical-instance floor, HTTP/TCP refusal-vs-unreachable semantics,
  the command-template trust boundary, and composite masking ("a running
  process does not mask a critical stale feed").
* :class:`TestServiceCrud` -- registry CRUD: defaults, slugs, validation,
  archive/read-only/restore, integer+slug addressing, list filters.
* :class:`TestInstances` -- per-(application, device, mechanism, target)
  instances: add/update/delete, duplicates, the roster check, the 100
  cap, disabled instances.
* :class:`TestTick` -- one health poll end-to-end against a real database
  and the shared state cache: transitions, "a failed check never erases
  the last success", snapshot persistence, rollups under criticality,
  the due-gated fleet spec map.
* :class:`TestProjectIntegration` -- the P1-R01 hook: an application's
  stored health feeds its project's rollup through the same source
  mechanism devices use.
* :class:`TestWeb` -- the HTTP surface: auth gating, viewer/admin roles,
  CRUD round trips, and secret redaction on every output.
* :class:`TestConfigValidation` -- the ``applications`` configuration
  section bounds, including the command-template allowlist.
* :class:`TestCollectorApps` -- the fleet collector's due-gated
  ``__APPS__`` section: argv construction, cadence, the spec hook, and the
  parse into ``DeviceState.app_checks``.
* :class:`TestHistoryRetention` -- ``HistoryManager.maintenance()``
  prunes application health snapshots on their own, longer retention.
"""
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pinoc.applications as applications
from pinoc.applications import ApplicationError, ApplicationService, strategy_names
from pinoc.collectors.fleet import FleetCollector, parse_app_checks
from pinoc.config_store import validate_applications
from pinoc.database import Database, MIGRATIONS, SCHEMA_VERSION
from pinoc.device_config import DeviceConfig
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.projects import ProjectService
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc
NOW = datetime.now(UTC)


class _RecordingHistory:
    """Duck-typed stand-in for HistoryManager in service-level tests:
    ApplicationService only calls ``event(...)`` on it (and inside a
    try/except), so a recorder is the cleanest way to assert transitions."""

    def __init__(self):
        self.events = []

    def event(self, device_id, event_type, severity, message, metadata=None):
        self.events.append({"device_id": device_id, "type": event_type,
                            "severity": severity, "message": message,
                            "metadata": metadata or {}})


def _record_audit(self, user, role, ip, device, action, target, params, auth,
                  result=None, exit_code=None, duration=None, error=None):
    self.audit.append({"user": user, "action": action, "target": target,
                       "params": params, "result": result})


def _device_row(self, device_id, hostname=None):
    self.db.execute(
        "INSERT INTO devices(device_id,hostname,friendly_name,created_at,updated_at) "
        "VALUES(?,?,?,?,?)",
        (device_id, hostname or device_id, device_id.title(),
         NOW.isoformat(), NOW.isoformat()))


def _setup_service(self, with_state=False):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.db = Database(f"{self._tmp.name}/db.sqlite")
    assert self.db.initialize()
    self.audit = []
    self.history = _RecordingHistory()
    self.state = PiNOCState() if with_state else None
    self.service = ApplicationService(
        self.db, state=self.state, history=self.history,
        config=getattr(self, "config", {}), audit=_record_audit.__get__(self, type(self)))
    self._device_row = lambda device_id, hostname=None: _device_row(
        self, device_id, hostname=hostname)


def completed(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["sh"], 0, stdout, "")


# A minimal complete fleet collection output (the same shape
# tests/test_service_logs.py uses) plus the due-gated __APPS__ section.
APPS_OUTPUT = """__OS__
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
eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0 0 0
__IW__
__JLOGS__
=== ssh
Jan 01 00:00:01 pi sshd[123]: Accepted publickey for pi
__SERVICES__
__UNITS__
ssh.service enabled
__APPS__
desk-web|pm2|running
__DRIFTFILES__
__SSHD__
"""


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------

class TestDatabaseSchema(unittest.TestCase):
    def test_schema_version_matches_migration_count(self):
        self.assertEqual(SCHEMA_VERSION, len(MIGRATIONS))
        self.assertEqual(SCHEMA_VERSION, 21)

    def test_application_tables_and_columns(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(f"{tmp.name}/db.sqlite")
        self.assertTrue(db.initialize())

        def columns(table):
            con = db.connect()
            try:
                return {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
            finally:
                con.close()

        app_columns = columns("applications")
        for column in ("app_id", "slug", "name", "description", "project_slug",
                       "lifecycle", "criticality", "version_source", "version",
                       "repository", "health_strategy_json", "endpoints_json",
                       "tags_json", "owner", "health", "health_reasons_json",
                       "last_success_at", "last_checked_at", "created_at",
                       "updated_at", "archived_at", "archived_reason"):
            self.assertIn(column, app_columns)
        instance_columns = columns("application_instances")
        for column in ("instance_id", "app_slug", "device_id", "mechanism",
                       "target", "critical", "enabled", "strategy_json", "health",
                       "health_reasons_json", "last_success_at", "last_checked_at"):
            self.assertIn(column, instance_columns)
        snapshot_columns = columns("application_health_snapshots")
        for column in ("snapshot_id", "app_slug", "instance_id", "device_id",
                       "health", "reasons_json", "strategy", "source",
                       "observed_at", "checked_at", "ttl_seconds", "confidence"):
            self.assertIn(column, snapshot_columns)


# ---------------------------------------------------------------------------
# strategies
# ---------------------------------------------------------------------------

class TestStrategies(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = _RecordingHistory()
        self.service = ApplicationService(
            self.db, state=None, history=self.history,
            config={"http_timeout_seconds": 2, "tcp_timeout_seconds": 2,
                    "freshness_seconds": 300})
        self.app = {"slug": "desk", "name": "Desk", "criticality": "standard",
                    "endpoints": []}
        self.now = NOW

    def _instance(self, **overrides):
        values = {"instance_id": 1, "app": "desk", "device_id": "pi",
                  "mechanism": "systemd", "target": "desk.service",
                  "critical": False, "enabled": True,
                  "strategy": {"strategy": "service", "unit": "desk.service"},
                  "health": "unknown", "health_reasons": [],
                  "last_success_at": None, "last_checked_at": None}
        values.update(overrides)
        return values

    def _device(self, **overrides):
        values = {"id": "pi", "hostname": "pi", "friendly_name": "Pi",
                  "online": True,
                  "services": [{"name": "desk.service", "state": "running"}],
                  "app_checks": [], "integrations": {}}
        values.update(overrides)
        return values

    def test_registry_holds_the_builtin_strategies(self):
        self.assertEqual(strategy_names(),
                         ["command", "composite", "http", "integration",
                          "process", "service", "tcp"])

    # -- service -----------------------------------------------------------
    def test_service_strategy_observations(self):
        fn = applications._strategy_service
        instance = self._instance()
        # No state for the device at all: nothing learned.
        result = fn(self.service, self.app, instance, None, self.now)
        self.assertFalse(result["conclusive"])
        self.assertEqual(result["state"], "unknown")
        # An offline host is a real observation, not a gap.
        result = fn(self.service, self.app, instance,
                    self._device(online=False), self.now)
        self.assertTrue(result["conclusive"])
        self.assertEqual(result["state"], "offline")
        # Running (or activating) is healthy.
        for state in ("running", "activating"):
            result = fn(self.service, self.app, instance,
                        self._device(services=[{"name": "desk.service", "state": state}]),
                        self.now)
            self.assertTrue(result["conclusive"])
            self.assertEqual(result["state"], "healthy")
        # Stopped: warning -- degraded when the instance is flagged critical.
        stopped = self._device(services=[{"name": "desk.service", "state": "stopped"}])
        self.assertEqual(fn(self.service, self.app, instance, stopped, self.now)["state"],
                         "warning")
        critical = self._instance(critical=True)
        self.assertEqual(fn(self.service, self.app, critical, stopped, self.now)["state"],
                         "degraded")
        # Failed: degraded -- critical when the instance is flagged critical.
        failed = self._device(services=[{"name": "desk.service", "state": "failed"}])
        self.assertEqual(fn(self.service, self.app, instance, failed, self.now)["state"],
                         "degraded")
        self.assertEqual(fn(self.service, self.app, critical, failed, self.now)["state"],
                         "critical")
        # The unit is simply not reported by this host: inconclusive.
        self.assertFalse(fn(self.service, self.app, instance,
                            self._device(services=[]), self.now)["conclusive"])
        # A state the strategy does not interpret: inconclusive, never guessed.
        loading = self._device(services=[{"name": "desk.service", "state": "loading"}])
        self.assertFalse(fn(self.service, self.app, instance, loading, self.now)["conclusive"])

    # -- process -----------------------------------------------------------
    def test_process_strategy_observations(self):
        fn = applications._strategy_process
        instance = self._instance(mechanism="pm2", target="desk-web",
                                  strategy={"strategy": "process", "name": "desk-web",
                                            "kind": "pm2"})
        running = self._device(app_checks=[{"name": "desk-web", "kind": "pm2",
                                            "status": "running"}])
        self.assertEqual(fn(self.service, self.app, instance, running, self.now)["state"],
                         "healthy")
        stopped = self._device(app_checks=[{"name": "desk-web", "kind": "pm2",
                                            "status": "stopped"}])
        self.assertEqual(fn(self.service, self.app, instance, stopped, self.now)["state"],
                         "warning")
        self.assertEqual(fn(self.service, self.app,
                            self._instance(critical=True, **{k: v for k, v in
                                                             instance.items() if k != "critical"}),
                            stopped, self.now)["state"], "degraded")
        # A host without the tool reports "unknown": inconclusive.
        unknown = self._device(app_checks=[{"name": "desk-web", "kind": "pm2",
                                            "status": "unknown"}])
        self.assertFalse(fn(self.service, self.app, instance, unknown, self.now)["conclusive"])
        # The host reported nothing for this (name, kind): inconclusive -- the
        # instance must age under its freshness floor instead of flapping.
        self.assertFalse(fn(self.service, self.app, instance,
                            self._device(app_checks=[]), self.now)["conclusive"])

    # -- http ---------------------------------------------------------------
    def test_http_strategy_observations(self):
        handler = type("Handler", (BaseHTTPRequestHandler,), {
            "do_GET": lambda self: (
                self.send_response(200 if self.path == "/ok" else
                                   404 if self.path == "/missing" else 500),
                self.end_headers(),
                self.wfile.write(b"x")),
            "log_message": lambda *args: None,
        })
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        fn = applications._strategy_http

        def check(path, critical=False, device=None):
            instance = self._instance(critical=critical,
                                      strategy={"strategy": "http", "url": base + path})
            return fn(self.service, self.app, instance, device, self.now)

        ok = check("/ok")
        self.assertTrue(ok["conclusive"])
        self.assertEqual(ok["state"], "healthy")
        self.assertEqual(check("/missing")["state"], "warning")
        self.assertEqual(check("/missing", critical=True)["state"], "degraded")
        self.assertEqual(check("/err")["state"], "degraded")
        self.assertEqual(check("/err", critical=True)["state"], "critical")
        # A refused connection: the host answered, so this is conclusive
        # ("the service is down"), not a network mystery.
        refused = fn(self.service, self.app,
                     self._instance(strategy={"strategy": "http",
                                              "url": "http://127.0.0.1:1/"}),
                     None, self.now)
        self.assertTrue(refused["conclusive"])
        self.assertEqual(refused["state"], "warning")
        # DNS failure: the network, not the service, is the unknown.
        unreachable = fn(self.service, self.app,
                         self._instance(strategy={"strategy": "http",
                                                  "url": "http://no-such-host.invalid/"}),
                         None, self.now)
        self.assertFalse(unreachable["conclusive"])
        self.assertEqual(unreachable["state"], "unknown")
        # No URL of its own: falls back to the application's first endpoint.
        app_with_endpoint = {**self.app, "endpoints": [base + "/ok"]}
        fallback = fn(self.service, app_with_endpoint,
                      self._instance(strategy={"strategy": "http"}), None, self.now)
        self.assertEqual(fallback["state"], "healthy")
        # No URL and no endpoints: inconclusive.
        self.assertFalse(fn(self.service, self.app,
                            self._instance(strategy={"strategy": "http"}),
                            None, self.now)["conclusive"])
        # An offline host beats even a URL: no point checking endpoints on it.
        offline = fn(self.service, self.app,
                     self._instance(strategy={"strategy": "http", "url": base + "/ok"}),
                     self._device(online=False), self.now)
        self.assertEqual(offline["state"], "offline")

    # -- tcp -----------------------------------------------------------------
    def test_tcp_strategy_observations(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        fn = applications._strategy_tcp

        def check(host, port_):
            return fn(self.service, self.app,
                      self._instance(strategy={"strategy": "tcp", "host": host,
                                               "port": port_}),
                      None, self.now)

        opened = check("127.0.0.1", port)
        self.assertTrue(opened["conclusive"])
        self.assertEqual(opened["state"], "healthy")
        refused = check("127.0.0.1", 1)  # the host answers: the service is down
        self.assertTrue(refused["conclusive"])
        self.assertEqual(refused["state"], "warning")
        critical = fn(self.service, self.app,
                      self._instance(critical=True,
                                     strategy={"strategy": "tcp", "host": "127.0.0.1",
                                               "port": 1}),
                      None, self.now)
        self.assertEqual(critical["state"], "degraded")
        unreachable = check("no-such-host.invalid", 80)  # DNS: cannot tell
        self.assertFalse(unreachable["conclusive"])
        self.assertEqual(unreachable["state"], "unknown")
        # Missing host/port: inconclusive.
        self.assertFalse(fn(self.service, self.app,
                            self._instance(strategy={"strategy": "tcp"}),
                            None, self.now)["conclusive"])

    # -- command ---------------------------------------------------------------
    def test_command_strategy_runs_registered_templates_only(self):
        self.service.command_templates = {
            "ok": {"command": "true", "timeout_seconds": 10},
            "fail": {"command": "false", "timeout_seconds": 10},
            "slow": {"command": "sleep 5", "timeout_seconds": 1},
        }
        fn = applications._strategy_command

        def check(template, critical=False):
            return fn(self.service, self.app,
                      self._instance(critical=critical,
                                     strategy={"strategy": "command",
                                               "template": template}),
                      None, self.now)

        ok = check("ok")
        self.assertTrue(ok["conclusive"])
        self.assertEqual(ok["state"], "healthy")
        fail = check("fail")
        self.assertTrue(fail["conclusive"])
        self.assertEqual(fail["state"], "warning")
        self.assertIn("exited 1", fail["reasons"][0])
        self.assertEqual(check("fail", critical=True)["state"], "degraded")
        # A template the API references but the operator never registered:
        # inconclusive -- the trust boundary holds.
        ghost = check("ghost")
        self.assertFalse(ghost["conclusive"])
        self.assertIn("not registered", ghost["reasons"][0])
        # A hung template: the bound timeout makes it inconclusive, quickly.
        started = time.monotonic()
        slow = check("slow")
        self.assertFalse(slow["conclusive"])
        self.assertLess(time.monotonic() - started, 4.5)

    # -- integration ------------------------------------------------------------
    def test_integration_strategy_reads_device_integrations(self):
        fn = applications._strategy_integration
        instance = self._instance(strategy={"strategy": "integration", "name": "raid"})
        for raw, expected in (("healthy", "healthy"), ("warning", "warning"),
                              ("degraded", "degraded"), ("critical", "critical")):
            device = self._device(integrations={"raid": {"health": raw}})
            result = fn(self.service, self.app, instance, device, self.now)
            self.assertTrue(result["conclusive"])
            self.assertEqual(result["state"], expected)
        # "unavailable"/"unsupported" are not health answers: inconclusive.
        for raw in ("unavailable", "unsupported"):
            device = self._device(integrations={"raid": {"health": raw}})
            self.assertFalse(fn(self.service, self.app, instance, device, self.now)["conclusive"])
        # The device reports no such integration: inconclusive.
        self.assertFalse(fn(self.service, self.app, instance,
                            self._device(integrations={}), self.now)["conclusive"])

    # -- composite ---------------------------------------------------------------
    def test_composite_healthy_child_does_not_mask_critical_failing_child(self):
        self.service.command_templates = {"fail": {"command": "false", "timeout_seconds": 10}}
        app = {**self.app, "criticality": "critical"}
        instance = self._instance(strategy={
            "strategy": "composite",
            "strategies": [
                # Observed healthy...
                {"strategy": "process", "name": "desk-web", "kind": "pm2"},
                # ...but a flagged-critical failing child escalates under the
                # application's criticality before the worst-of is taken.
                {"strategy": "command", "template": "fail", "critical": True},
            ]})
        device = self._device(app_checks=[{"name": "desk-web", "kind": "pm2",
                                           "status": "running"}])
        result = applications._strategy_composite(self.service, app, instance,
                                                  device, self.now)
        self.assertTrue(result["conclusive"])
        self.assertEqual(result["state"], "degraded")  # worst(healthy, degraded)

    def test_composite_inconclusive_child_ages_under_the_freshness_floor(self):
        app = {**self.app, "criticality": "critical"}
        two_hours_ago = (NOW - timedelta(hours=2)).isoformat()
        instance = self._instance(health="healthy", last_success_at=two_hours_ago,
                                  strategy={
                                      "strategy": "composite",
                                      "strategies": [
                                          {"strategy": "process", "name": "desk-web",
                                           "kind": "pm2"},
                                          {"strategy": "tcp", "host": "no-such-host.invalid",
                                           "port": 80, "critical": True},
                                      ]})
        device = self._device(app_checks=[{"name": "desk-web", "kind": "pm2",
                                           "status": "running"}])
        result = applications._strategy_composite(self.service, app, instance,
                                                  device, self.now)
        # The unreachable child floors at "stale" (last success aged out) and
        # escalates to critical under the app's criticality -- the healthy
        # sibling cannot pull the average back down.
        self.assertEqual(result["state"], "critical")
        self.assertTrue(any("tcp" in reason for reason in result["reasons"]))

    def test_composite_without_children_is_inconclusive(self):
        result = applications._strategy_composite(self.service, self.app,
                                                  self._instance(strategy={
                                                      "strategy": "composite"}),
                                                  self._device(), self.now)
        self.assertFalse(result["conclusive"])

    def test_composite_unknown_child_counts_as_unknown(self):
        instance = self._instance(strategy={
            "strategy": "composite",
            "strategies": [{"strategy": "not-a-real-strategy"}]})
        result = applications._strategy_composite(self.service, self.app, instance,
                                                  self._device(), self.now)
        self.assertEqual(result["state"], "unknown")
        self.assertTrue(any("not-a-real-strategy" in reason for reason in result["reasons"]))

    # -- the observation contract ---------------------------------------------------
    def test_finalize_conclusive_healthy_refreshes_last_success(self):
        old = (NOW - timedelta(hours=2)).isoformat()
        instance = self._instance(health="stale", last_success_at=old)
        health, reasons, last_success = self.service._finalize(
            instance, {"state": "healthy", "conclusive": True, "reasons": []},
            self.now, self.now.isoformat())
        self.assertEqual(health, "healthy")
        self.assertEqual(last_success, self.now.isoformat())
        self.assertEqual(reasons, [])

    def test_finalize_failed_check_keeps_last_success(self):
        old = (NOW - timedelta(hours=2)).isoformat()
        instance = self._instance(health="healthy", last_success_at=old)
        health, _reasons, last_success = self.service._finalize(
            instance, {"state": "warning", "conclusive": True,
                       "reasons": ["unit is stopped"]},
            self.now, self.now.isoformat())
        self.assertEqual(health, "warning")
        self.assertEqual(last_success, old)  # never erased by a failure

    def test_finalize_inconclusive_ages_under_floor_without_erasing_success(self):
        old = (NOW - timedelta(hours=2)).isoformat()  # older than the 300s floor
        instance = self._instance(health="healthy", last_success_at=old)
        health, reasons, last_success = self.service._finalize(
            instance, {"state": "unknown", "conclusive": False,
                       "reasons": ["host unreachable"]},
            self.now, self.now.isoformat())
        self.assertEqual(health, "stale")
        self.assertEqual(last_success, old)
        self.assertIn("last confirmed", reasons[0])
        # A never-checked object has no success to age: it reads unknown.
        fresh, _r, ls = self.service._finalize(
            self._instance(last_success_at=None),
            {"state": "unknown", "conclusive": False, "reasons": ["host unreachable"]},
            self.now, self.now.isoformat())
        self.assertEqual(fresh, "unknown")
        self.assertIsNone(ls)

    def test_meaningful_transition_suppresses_quiet_startup(self):
        fn = applications._meaningful_transition
        self.assertFalse(fn("unknown", "unknown"))
        self.assertFalse(fn("unknown", "healthy"))
        self.assertFalse(fn("unknown", "maintenance"))
        self.assertTrue(fn("unknown", "warning"))
        self.assertTrue(fn("unknown", "stale"))
        self.assertFalse(fn("healthy", "healthy"))
        self.assertTrue(fn("healthy", "stale"))
        self.assertTrue(fn("warning", "healthy"))

    # -- payload codecs ---------------------------------------------------------------
    def test_load_strategy_normalizes_and_validates(self):
        templates = {"ok": {"command": "true", "timeout_seconds": 10}}
        self.assertEqual(applications._load_strategy(None, "strategy", templates), {})
        self.assertEqual(applications._load_strategy("http", "strategy", templates),
                         {"strategy": "http"})
        strategy = applications._load_strategy(
            {"strategy": "tcp", "host": "10.0.0.5", "port": 9000, "critical": True},
            "strategy", templates)
        self.assertEqual(strategy, {"strategy": "tcp", "host": "10.0.0.5",
                                    "port": 9000, "critical": True})
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "bogus"}, "strategy", templates)
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "command"}, "strategy", templates)
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "command", "template": "ghost"},
                                        "strategy", templates)
        self.assertEqual(
            applications._load_strategy({"strategy": "command", "template": "ok"},
                                        "strategy", templates)["template"], "ok")
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "http", "url": "ftp://x.example"},
                                        "strategy", templates)
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "tcp", "port": 70000},
                                        "strategy", templates)
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "composite", "strategies": "nope"},
                                        "strategy", templates)
        with self.assertRaises(ApplicationError):
            applications._load_strategy({"strategy": "composite", "strategies": []},
                                        "strategy", templates)
        nested = applications._load_strategy(
            {"strategy": "composite",
             "strategies": [{"strategy": "http", "url": "https://a.example"},
                            {"strategy": "tcp", "host": "b.example", "port": 80}]},
            "strategy", templates)
        self.assertEqual(len(nested["strategies"]), 2)

    def test_load_endpoints_and_tags(self):
        self.assertEqual(applications._load_endpoints(None), [])
        values = applications._load_endpoints("https://a.example/x, 192.168.1.5:9000")
        self.assertEqual(values, ["https://a.example/x", "192.168.1.5:9000"])
        with self.assertRaises(ApplicationError):
            applications._load_endpoints(["not-a-url"])
        with self.assertRaises(ApplicationError):
            applications._load_endpoints([f"https://x{i}.example" for i in range(51)])
        self.assertEqual(applications._load_tags("a, b ,"), ["a", "b"])
        with self.assertRaises(ApplicationError):
            applications._load_tags(["tag"] * 51)


# ---------------------------------------------------------------------------
# service CRUD
# ---------------------------------------------------------------------------

class TestServiceCrud(unittest.TestCase):
    def setUp(self):
        _setup_service(self)

    def _record_audit(self, *args, **kwargs):
        _record_audit(self, *args, **kwargs)

    def test_create_defaults_and_round_trip(self):
        app = self.service.create({"name": "Desk Display"})
        self.assertEqual(app["id"], "desk-display")
        self.assertEqual(app["slug"], "desk-display")
        self.assertEqual(app["lifecycle"], "active")  # applications default active
        self.assertEqual(app["criticality"], "standard")
        self.assertEqual(app["version_source"], "manual")
        self.assertIsNone(app["version"])
        self.assertIsNone(app["repository"])
        self.assertIsNone(app["project"])
        self.assertEqual(app["strategy"], {})
        self.assertEqual(app["endpoints"], [])
        self.assertEqual(app["tags"], [])
        self.assertEqual(app["health"], "unknown")
        self.assertFalse(app["archived"])
        self.assertEqual(app["instance_count"], 0)
        self.assertIn("application.create", [a["action"] for a in self.audit])
        # Both the slug and the integer id address the same row.
        self.assertEqual(self.service.get("desk-display")["name"], "Desk Display")
        self.assertEqual(self.service.get(app["app_id"])["id"], "desk-display")

    def test_create_duplicate_slug_rejected(self):
        self.service.create({"name": "Desk Display"})
        with self.assertRaises(ApplicationError):
            self.service.create({"name": "Desk Display"})  # same derived slug
        with self.assertRaises(ApplicationError):
            self.service.create({"name": "Other", "slug": "desk-display"})

    def test_create_rejects_invalid_input(self):
        for payload in ({}, {"name": ""}, {"name": "x" * 201},
                        {"name": "Ok", "slug": "Bad Slug"},
                        {"name": "Ok", "lifecycle": "archived"},
                        {"name": "Ok", "lifecycle": "exploded"},
                        {"name": "Ok", "criticality": "apocalyptic"},
                        {"name": "Ok", "version_source": "crystal-ball"},
                        {"name": "Ok", "repository": "not a url"},
                        {"name": "Ok", "project": "no-such-project"},
                        {"name": "Ok", "strategy": {"strategy": "bogus"}},
                        {"name": "Ok", "endpoints": ["nope"]}):
            with self.assertRaises(ApplicationError):
                self.service.create(payload)

    def test_create_stores_metadata(self):
        app = self.service.create({
            "name": "ADS-B", "description": "Ground station", "lifecycle": "planned",
            "criticality": "high", "owner": "jason", "tags": ["aviation"],
            "version": "v2.1", "version_source": "git_tag",
            "repository": "https://github.com/example/adsb.git",
            "endpoints": ["https://example.com/api", "192.168.1.5:30001"],
            "strategy": "http",
        })
        self.assertEqual(app["lifecycle"], "planned")
        self.assertEqual(app["criticality"], "high")
        self.assertEqual(app["version"], "v2.1")
        self.assertEqual(app["version_source"], "git_tag")
        self.assertEqual(app["repository"], "https://github.com/example/adsb.git")
        self.assertEqual(app["owner"], "jason")
        self.assertEqual(app["tags"], ["aviation"])
        self.assertEqual(app["endpoints"], ["https://example.com/api", "192.168.1.5:30001"])
        self.assertEqual(app["strategy"], {"strategy": "http"})
        self.assertIsNotNone(self.service.get(app["app_id"]))

    def test_update_fields_and_audits(self):
        self.service.create({"name": "Desk Display"})
        app = self.service.update("desk-display", {
            "name": "Desk Display v2", "description": "new", "owner": "jason",
            "tags": ["kiosk"], "criticality": "critical", "lifecycle": "maintenance",
            "version": "1.0", "repository": "git@github.com:example/repo.git",
            "strategy": {"strategy": "service", "unit": "desk.service"},
        })
        self.assertEqual(app["name"], "Desk Display v2")
        self.assertEqual(app["criticality"], "critical")
        self.assertEqual(app["lifecycle"], "maintenance")
        self.assertEqual(app["strategy"], {"strategy": "service", "unit": "desk.service"})
        actions = {a["action"] for a in self.audit}
        self.assertIn("application.update", actions)
        self.assertIn("application.criticality", actions)
        self.assertIn("application.lifecycle", actions)
        self.assertIn("application.strategy", actions)

    def test_update_validates_against_registry(self):
        self.service.create({"name": "Desk"})
        with self.assertRaises(ApplicationError):
            self.service.update("desk", {"project": "ghost-project"})
        with self.assertRaises(ApplicationError):
            self.service.update("desk", {"lifecycle": "archived"})
        with self.assertRaises(ApplicationError):
            self.service.update("desk", {"criticality": "apocalyptic"})
        with self.assertRaises(ApplicationError):
            self.service.update("desk", {"repository": "not a url"})
        # Unknown application: 404-shaped error.
        with self.assertRaises(ApplicationError) as ctx:
            self.service.update("ghost", {"name": "x"})
        self.assertIn("not found", str(ctx.exception))

    def test_archive_makes_application_read_only(self):
        self._device_row("pi")
        self.service.create({"name": "Desk"})
        self.service.add_instance("desk", {"device_id": "pi", "target": "desk.service"})
        archived = self.service.archive("desk", actor="bob", reason="retiring")
        self.assertEqual(archived["lifecycle"], "archived")
        self.assertTrue(archived["archived"])
        self.assertIsNotNone(archived["archived_at"])
        self.assertEqual(archived["archived_reason"], "retiring")
        for write in (lambda: self.service.update("desk", {"name": "nope"}),
                      lambda: self.service.add_instance(
                          "desk", {"device_id": "pi", "target": "other.service"}),
                      lambda: self.service.delete_instance("desk", 1)):
            with self.assertRaises(ApplicationError) as ctx:
                write()
            self.assertIn("read-only", str(ctx.exception))
        # Archiving again is a no-op (no duplicate audit row).
        before = len(self.audit)
        self.assertEqual(self.service.archive("desk")["lifecycle"], "archived")
        self.assertEqual(len(self.audit), before)

    def test_restore_round_trip(self):
        self.service.create({"name": "Desk"})
        with self.assertRaises(ApplicationError):
            self.service.restore("desk")  # only archived applications
        self.service.archive("desk")
        restored = self.service.restore("desk", actor="bob")
        self.assertEqual(restored["lifecycle"], "active")
        self.assertIsNone(restored["archived_at"])
        self.assertIsNone(restored["archived_reason"])

    def test_list_filters(self):
        self.service.create({"name": "Alpha", "lifecycle": "active"})
        self.service.create({"name": "Beta", "lifecycle": "planned"})
        self.service.create({"name": "Gamma"})
        self.service.archive("gamma")
        self.assertEqual([a["id"] for a in self.service.list()], ["alpha", "beta"])
        self.assertEqual({a["id"] for a in self.service.list(include_archived=True)},
                         {"alpha", "beta", "gamma"})
        self.assertEqual([a["id"] for a in self.service.list(lifecycle="planned")],
                         ["beta"])
        with self.assertRaises(ApplicationError):
            self.service.list(lifecycle="bogus")

    def test_list_filters_by_project_and_counts_instances(self):
        projects = ProjectService(self.db, audit=_record_audit.__get__(self, type(self)))
        projects.create({"name": "Display"})
        self.service.create({"name": "Desk", "project": "display"})
        self.service.create({"name": "Spare"})
        self._device_row("pi")
        self.service.add_instance("desk", {"device_id": "pi", "target": "desk.service"})
        self.service.add_instance("desk", {"device_id": "pi", "mechanism": "pm2",
                                           "target": "desk-web"})
        self.assertEqual([a["id"] for a in self.service.list(project="display")],
                         ["desk"])
        listed = {a["id"]: a["instance_count"] for a in self.service.list()}
        self.assertEqual(listed["desk"], 2)
        self.assertEqual(listed["spare"], 0)

    def test_get_returns_instances_with_device_info(self):
        self._device_row("pi")
        self.service.create({"name": "Desk"})
        self.service.add_instance("desk", {"device_id": "pi", "target": "desk.service"})
        detail = self.service.get("desk")
        self.assertEqual(len(detail["instances"]), 1)
        self.assertEqual(detail["instances"][0]["device"],
                         {"id": "pi", "hostname": "pi", "friendly_name": "Pi",
                          "online": False})  # no live state -> offline read
        self.assertIsNone(self.service.get("ghost"))

    def test_no_database_degrades_to_empty(self):
        service = ApplicationService(None)
        self.assertEqual(service.list(), [])
        self.assertIsNone(service.get("desk"))
        with self.assertRaises(ApplicationError):
            service.instances("desk")  # unknown app: 404-shaped, not an empty list
        self.assertEqual(service.device_app_specs(), {})
        with self.assertRaises(ApplicationError):
            service.create({"name": "Desk"})
        with self.assertRaises(ApplicationError):
            service.archive("desk")


# ---------------------------------------------------------------------------
# instances
# ---------------------------------------------------------------------------

class TestInstances(unittest.TestCase):
    def setUp(self):
        _setup_service(self)
        self._device_row("pi")
        self._device_row("spare")
        self.app = self.service.create({"name": "Desk", "slug": "desk"})
        self.instance = self.service.add_instance(
            "desk", {"device_id": "pi", "mechanism": "systemd",
                     "target": "desk.service"})

    def _record_audit(self, *args, **kwargs):
        _record_audit(self, *args, **kwargs)

    def test_add_instance_defaults(self):
        self.assertEqual(self.instance["mechanism"], "systemd")
        self.assertEqual(self.instance["target"], "desk.service")
        self.assertFalse(self.instance["critical"])
        self.assertTrue(self.instance["enabled"])
        self.assertEqual(self.instance["strategy"], {})
        self.assertEqual(self.instance["health"], "unknown")
        self.assertIsNone(self.instance["last_success_at"])
        self.assertIn("application.instance.add",
                      [a["action"] for a in self.audit])

    def test_add_instance_unknown_device_rejected(self):
        # The roster (devices table) is non-empty, so unknown ids are refused.
        with self.assertRaises(ApplicationError) as ctx:
            self.service.add_instance("desk", {"device_id": "ghost"})
        self.assertIn("unknown device", str(ctx.exception))

    def test_add_instance_validates_payload(self):
        for payload in ({"device_id": "pi"},  # no target
                        {"device_id": "pi", "target": ""},
                        {"device_id": "pi", "target": "desk service"},
                        {"device_id": "pi", "mechanism": "ansible", "target": "x"},
                        {"device_id": "", "target": "x"}):
            with self.assertRaises(ApplicationError):
                self.service.add_instance("desk", payload)

    def test_duplicate_instance_rejected(self):
        with self.assertRaises(ApplicationError) as ctx:
            self.service.add_instance("desk", {"device_id": "pi", "mechanism": "systemd",
                                               "target": "desk.service"})
        self.assertIn("already exists", str(ctx.exception))
        # Same unit on a *different* device is a second instance, not a duplicate.
        second = self.service.add_instance("desk", {"device_id": "spare", "target": "desk.service"})
        self.assertNotEqual(second["instance_id"], self.instance["instance_id"])
        self.assertEqual(len(self.service.instances("desk")), 2)

    def test_one_application_two_devices(self):
        self.service.add_instance("desk", {"device_id": "spare", "target": "desk.service"})
        instances = self.service.get("desk")["instances"]
        self.assertEqual(len(instances), 2)
        self.assertEqual({i["device_id"] for i in instances}, {"pi", "spare"})
        self.assertEqual(instances[0]["device"]["friendly_name"], "Pi")

    def test_instance_limit(self):
        for i in range(99):
            self.service.add_instance(
                "desk", {"device_id": "pi", "mechanism": "systemd",
                         "target": f"unit-{i}.service"})
        with self.assertRaises(ApplicationError):
            self.service.add_instance(
                "desk", {"device_id": "pi", "target": "unit-100.service"})

    def test_update_instance_fields(self):
        updated = self.service.update_instance(
            "desk", self.instance["instance_id"],
            {"critical": True, "enabled": False, "target": "desk@1.service",
             "strategy": {"strategy": "process", "name": "desk-web", "kind": "pm2"}})
        self.assertTrue(updated["critical"])
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["target"], "desk@1.service")
        self.assertEqual(updated["strategy"],
                         {"strategy": "process", "name": "desk-web", "kind": "pm2"})
        with self.assertRaises(ApplicationError):
            self.service.update_instance("desk", self.instance["instance_id"],
                                         {"mechanism": "ansible"})
        with self.assertRaises(ApplicationError):
            self.service.update_instance("desk", self.instance["instance_id"],
                                         {"target": "bad target"})
        # A non-numeric instance id is a 404-shaped error, never a 500.
        with self.assertRaises(ApplicationError) as ctx:
            self.service.update_instance("desk", "not-a-number", {"critical": True})
        self.assertIn("not found", str(ctx.exception))

    def test_update_instance_target_conflict(self):
        self.service.add_instance("desk", {"device_id": "pi", "target": "other.service"})
        with self.assertRaises(ApplicationError):
            self.service.update_instance("desk", self.instance["instance_id"],
                                         {"target": "other.service"})

    def test_delete_instance_removes_row_and_snapshots(self):
        stamp = NOW.isoformat()
        self.db.execute(
            "INSERT INTO application_health_snapshots(app_slug,instance_id,device_id,health,"
            "reasons_json,strategy,source,observed_at,checked_at,ttl_seconds,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("desk", self.instance["instance_id"], "pi", "healthy", "[]",
             "service", "strategy", stamp, stamp, 300, 1.0))
        self.service.delete_instance("desk", self.instance["instance_id"])
        self.assertEqual(self.service.instances("desk"), [])
        self.assertEqual(self.db.scalar(
            "SELECT COUNT(*) FROM application_health_snapshots WHERE instance_id=?",
            (self.instance["instance_id"],)), 0)
        # Deleting again: not found.
        with self.assertRaises(ApplicationError):
            self.service.delete_instance("desk", self.instance["instance_id"])

    def test_add_instance_to_archived_app_rejected(self):
        self.service.archive("desk")
        with self.assertRaises(ApplicationError):
            self.service.add_instance("desk", {"device_id": "pi", "target": "x.service"})


# ---------------------------------------------------------------------------
# the health poll
# ---------------------------------------------------------------------------

class TestTick(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._publish()
        self.app = self.service.create({"name": "Desk", "slug": "desk"})
        self.instance = self.service.add_instance(
            "desk", {"device_id": "pi", "mechanism": "systemd",
                     "target": "desk.service"})

    def _record_audit(self, *args, **kwargs):
        _record_audit(self, *args, **kwargs)

    def _publish(self, spare: bool = False, **overrides):
        values = {"id": "pi", "hostname": "pi", "friendly_name": "Pi",
                  "online": True,
                  "services": [{"name": "desk.service", "state": "running"}]}
        values.update(overrides)
        devices = [DeviceState(**values)]
        if spare:
            spare_values = {"id": "spare", "hostname": "spare",
                            "friendly_name": "Spare", "online": True,
                            "services": []}
            spare_values.update(overrides)
            devices.append(DeviceState(**spare_values))
        self.state.publish(devices, replace=True)

    def test_first_healthy_observation_is_quiet(self):
        result = self.service.tick(now=NOW)
        self.assertEqual(result["checked"], 1)
        instance = self.service.instances("desk")[0]
        self.assertEqual(instance["health"], "healthy")
        self.assertEqual(instance["last_success_at"], NOW.isoformat())
        self.assertIsNotNone(instance["last_checked_at"])
        self.assertEqual(self.service.get("desk")["health"], "healthy")
        # unknown -> healthy is a quiet startup observation: no page.
        self.assertEqual(self.history.events, [])
        snapshot = self.db.rows("SELECT * FROM application_health_snapshots")[0]
        self.assertEqual(snapshot["strategy"], "service")
        self.assertEqual(snapshot["source"], "strategy")
        self.assertEqual(snapshot["device_id"], "pi")
        self.assertEqual(snapshot["health"], "healthy")
        self.assertEqual(snapshot["confidence"], 1.0)
        self.assertEqual(snapshot["ttl_seconds"], 300)

    def test_transition_emits_events_and_failed_check_keeps_last_success(self):
        self.service.tick(now=NOW)
        first_success = self.service.instances("desk")[0]["last_success_at"]
        self._publish(services=[{"name": "desk.service", "state": "stopped"}])
        self.service.tick(now=NOW + timedelta(seconds=10))
        instance = self.service.instances("desk")[0]
        self.assertEqual(instance["health"], "warning")
        self.assertEqual(instance["last_success_at"], first_success)
        instance_events = [e for e in self.history.events
                           if e["metadata"].get("instance_id")]
        self.assertEqual(len(instance_events), 1)
        event = instance_events[0]
        self.assertEqual(event["device_id"], "pi")
        self.assertEqual(event["type"], "application_health_changed")
        self.assertEqual(event["severity"], "warning")
        self.assertEqual(event["metadata"]["previous"], "healthy")
        self.assertEqual(event["metadata"]["current"], "warning")
        self.assertEqual(event["metadata"]["mechanism"], "systemd")
        self.assertEqual(event["metadata"]["target"], "desk.service")
        # The application rollup moved too, under the synthetic device id.
        app_events = [e for e in self.history.events
                      if e["device_id"] == "pinoc-applications"]
        self.assertEqual(len(app_events), 1)
        self.assertEqual(app_events[0]["metadata"]["current"], "warning")
        self.assertEqual(self.service.get("desk")["health"], "warning")

    def test_device_offline_moves_instance_to_offline(self):
        self.service.tick(now=NOW)
        self._publish(online=False)
        self.service.tick(now=NOW + timedelta(seconds=5))
        self.assertEqual(self.service.instances("desk")[0]["health"], "offline")
        events = [e for e in self.history.events
                  if e["metadata"].get("current") == "offline"]
        self.assertTrue(events)
        self.assertEqual(events[0]["severity"], "critical")
        self.assertEqual(self.service.get("desk")["health"], "offline")

    def test_inconclusive_check_ages_under_floor_without_erasing_success(self):
        self.service.tick(now=NOW)
        self._publish(services=[])  # the unit is no longer reported: inconclusive
        self.service.tick(now=NOW + timedelta(hours=2))  # past the 300s floor
        instance = self.service.instances("desk")[0]
        self.assertEqual(instance["health"], "stale")
        self.assertEqual(instance["last_success_at"], NOW.isoformat())
        self.assertIn("last confirmed", instance["health_reasons"][0])
        # healthy -> stale is a real change: one event, snapshot confidence < 1.
        self.assertTrue(self.history.events)
        snapshot = self.db.rows(
            "SELECT * FROM application_health_snapshots ORDER BY snapshot_id DESC")[0]
        self.assertEqual(snapshot["health"], "stale")
        self.assertLess(snapshot["confidence"], 1.0)

    def test_app_rollup_escalates_by_criticality(self):
        self.service.update("desk", {"criticality": "critical"})
        self.service.tick(now=NOW)
        self._publish(services=[{"name": "desk.service", "state": "stopped"}])
        self.service.tick(now=NOW + timedelta(seconds=5))
        app = self.service.get("desk")
        self.assertEqual(app["health"], "degraded")  # warning escalated under critical
        self.assertEqual(app["health_reasons"], ["instance.degraded:1"])  # post-escalation

    def test_two_instances_on_two_devices_roll_up_to_worst(self):
        self._publish(spare=True)
        self.service.add_instance("desk", {"device_id": "spare",
                                           "mechanism": "pm2", "target": "desk-web"})
        # pi's unit stops (warning); spare's pm2 app is reported running.
        self._publish(spare=True,
                      app_checks=[{"name": "desk-web", "kind": "pm2",
                                   "status": "running"}],
                      services=[{"name": "desk.service", "state": "stopped"}])
        self.service.tick(now=NOW)
        app = self.service.get("desk")
        self.assertEqual(app["health"], "warning")
        self.assertEqual(app["health_reasons"], ["instance.warning:1"])

    def test_app_without_instances_reads_unknown(self):
        self.service.create({"name": "Empty", "slug": "empty"})
        result = self.service.tick(now=NOW)
        self.assertEqual(result["checked"], 2)
        entry = next(e for e in result["applications"] if e["id"] == "empty")
        self.assertEqual(entry["health"], "unknown")
        self.assertEqual(entry["reasons"], ["no enabled instances"])
        self.assertEqual(self.service.get("empty")["health"], "unknown")

    def test_archived_applications_are_not_ticked(self):
        self.service.archive("desk")
        result = self.service.tick(now=NOW)
        self.assertEqual(result["checked"], 0)
        self.assertEqual(result["applications"], [])

    def test_retired_application_reads_at_least_maintenance(self):
        self.service.update("desk", {"lifecycle": "retired"})
        self.service.tick(now=NOW)
        self.assertEqual(self.service.get("desk")["health"], "maintenance")
        self.assertEqual(self.history.events, [])  # unknown -> maintenance is quiet

    def test_disabled_instances_are_skipped(self):
        self.service.update_instance("desk", self.instance["instance_id"],
                                     {"enabled": False})
        result = self.service.tick(now=NOW)
        entry = next(e for e in result["applications"] if e["id"] == "desk")
        self.assertEqual(entry["instances"], 0)
        self.assertEqual(entry["health"], "unknown")

    def test_snapshots_accumulate_per_tick(self):
        self.service.tick(now=NOW)
        self.service.tick(now=NOW + timedelta(seconds=5))
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM application_health_snapshots"), 2)

    def test_health_endpoint_rereads_and_reages(self):
        self.service.tick(now=NOW)
        health = self.service.health("desk", now=NOW + timedelta(hours=2))
        # The stored rollup is what the last poll persisted...
        self.assertEqual(health["health"], "healthy")
        # ...but the display re-ages each instance past the floor.
        self.assertEqual(health["instances"][0]["health"], "stale")
        self.assertEqual(len(health["snapshots"]), 1)
        self.assertEqual(health["snapshots"][0]["health_normalized"], "healthy")
        self.assertEqual(health["instances"][0]["last_success_at"], NOW.isoformat())
        with self.assertRaises(ApplicationError):
            self.service.health("ghost")

    def test_device_app_specs_map(self):
        self.service.add_instance("desk", {"device_id": "pi", "mechanism": "pm2",
                                           "target": "desk-web"})
        self.service.create({"name": "Ghost", "slug": "ghost"})
        self.service.add_instance("ghost", {"device_id": "pi", "target": "ghost.service"})
        self.service.archive("ghost")
        specs = self.service.device_app_specs()
        self.assertEqual(sorted(specs.get("pi", [])),
                         ["pm2|desk-web", "systemd|desk.service"])
        self.assertNotIn("systemd|ghost.service", specs.get("pi", []))  # archived

    def test_disabled_instances_excluded_from_specs(self):
        other = self.service.add_instance("desk", {"device_id": "pi", "mechanism": "pm2",
                                                   "target": "desk-web"})
        self.service.update_instance("desk", other["instance_id"], {"enabled": False})
        self.assertEqual(self.service.device_app_specs()["pi"],
                         ["systemd|desk.service"])

    def test_tick_with_no_database_is_a_noop(self):
        service = ApplicationService(None, state=self.state)
        result = service.tick(now=NOW)
        self.assertEqual(result["checked"], 0)


# ---------------------------------------------------------------------------
# project registry hook (P1-R01)
# ---------------------------------------------------------------------------

class TestProjectIntegration(unittest.TestCase):
    def setUp(self):
        _setup_service(self)
        self.projects = ProjectService(self.db, audit=_record_audit.__get__(self, type(self)))

    def _record_audit(self, *args, **kwargs):
        _record_audit(self, *args, **kwargs)

    def _seed_app_health(self, slug, health):
        self.db.execute(
            "UPDATE applications SET health=?, health_reasons_json=?, "
            "last_checked_at=?, last_success_at=? WHERE slug=?",
            (health, "[]", NOW.isoformat(),
             NOW.isoformat() if health == "healthy" else None, slug))

    def test_application_health_feeds_project_rollup(self):
        self.service.create({"name": "Desk", "slug": "desk"})
        self.projects.create({"name": "Display", "slug": "display",
                              "criticality": "critical", "lifecycle": "active"})
        self.projects.add_members("display", "application", ["desk"])
        self._seed_app_health("desk", "stale")
        summary = self.projects.health("display")
        self.assertEqual(summary["health"], "critical")  # stale escalated under critical
        member = summary["members"]["application"][0]
        self.assertEqual(member["object_id"], "desk")
        self.assertEqual(member["health"], "stale")
        self.assertTrue(any("desk" in reason for reason in summary["reasons"]))

    def test_healthy_application_does_not_hurt_project(self):
        self.service.create({"name": "Desk", "slug": "desk"})
        self.projects.create({"name": "Display", "slug": "display"})
        self.projects.add_members("display", "application", ["desk"])
        self._seed_app_health("desk", "healthy")
        summary = self.projects.health("display")
        self.assertEqual(summary["health"], "healthy")
        self.assertEqual(summary["reasons"], [])

    def test_stale_application_escalates_by_project_criticality(self):
        self.service.create({"name": "Desk", "slug": "desk"})
        self.projects.create({"name": "Display", "slug": "display",
                              "criticality": "standard"})
        self.projects.add_members("display", "application", ["desk"])
        self._seed_app_health("desk", "stale")
        self.assertEqual(self.projects.health("display")["health"], "warning")

    def test_missing_application_reads_unknown(self):
        self.projects.create({"name": "Display", "slug": "display"})
        self.projects.add_members("display", "application", ["ghost-app"])
        summary = self.projects.health("display")
        entry = next(e for e in summary["members"]["application"]
                     if e["object_id"] == "ghost-app")
        self.assertEqual(entry["health"], "unknown")
        self.assertIn("not found", entry["reasons"][0])

    def test_application_roster_feeds_unassigned_inventory(self):
        self.service.create({"name": "Desk", "slug": "desk"})
        self.service.create({"name": "Spare", "slug": "spare"})
        self.service.create({"name": "Old", "slug": "old"})
        self.service.archive("old")
        self.projects.create({"name": "Display", "slug": "display"})
        self.projects.add_members("display", "application", ["desk"])
        result = self.projects.unassigned("application")
        self.assertEqual(result["assigned"], ["desk"])
        self.assertEqual(result["unassigned"], ["spare"])  # archived apps are out

    def test_application_memberships_are_audited(self):
        self.service.create({"name": "Desk", "slug": "desk"})
        self.projects.create({"name": "Display", "slug": "display"})
        added = self.projects.add_members("display", "application", ["desk"], actor="bob")
        self.assertEqual(added["added"], ["desk"])
        self.assertEqual(self.projects.members("display")["application"], ["desk"])
        removed = self.projects.remove_members("display", "application", ["desk"])
        self.assertEqual(removed["removed"], ["desk"])
        # Soft-removed kinds drop out of the grouped view.
        self.assertNotIn("application", self.projects.members("display"))


# ---------------------------------------------------------------------------
# web surface
# ---------------------------------------------------------------------------

class TestWeb(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                        health="healthy",
                        services=[{"name": "desk.service", "state": "running"}]),
        ], replace=True)
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True,
                         "SECRET_KEY": "test-secret", "DATABASE": self.db},
            self.history, None)
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("alice", "pw1234567890", "viewer")
        self.security.create_user("bob", "pw1234567890", "administrator")
        self.client = self.app.test_client()
        # Seed registry content outside the HTTP surface (the viewer below
        # cannot create it itself).
        self.service = self.app.extensions["pinoc_applications"]
        self.service.create({"name": "Seed", "slug": "seed"})

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()

    def _login(self, username, password="pw1234567890"):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post(
            "/login", data={"username": username, "password": password,
                            "csrf_token": csrf})

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path, body=None):
        return self.client.post(path, json=body or {},
                                headers={"X-CSRF-Token": self._csrf()})

    def _patch(self, path, body=None):
        return self.client.patch(path, json=body or {},
                                 headers={"X-CSRF-Token": self._csrf()})

    def _delete(self, path, body=None):
        return self.client.delete(path, json=body,
                                  headers={"X-CSRF-Token": self._csrf()})

    def _create_application(self, **extra):
        response = self._post("/api/v1/applications", {"name": "Desk", **extra})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()["application"]

    # -- auth gating -----------------------------------------------------------
    def test_unauthenticated_api_and_page(self):
        self.assertEqual(self.client.get("/api/v1/applications").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/applications/desk").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/applications/desk/health").status_code, 401)
        self.assertEqual(self.client.get("/applications").status_code, 302)  # -> login

    def test_viewer_reads_but_cannot_write(self):
        self._login("alice")
        self.assertEqual(self.client.get("/api/v1/applications").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/applications/seed").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/applications/seed/health").status_code, 200)
        self.assertEqual(self._post("/api/v1/applications", {"name": "Desk"}).status_code, 403)
        self.assertEqual(self._post("/api/v1/applications/seed/archive", {}).status_code, 403)
        self.assertEqual(
            self._post("/api/v1/applications/seed/instances",
                       {"device_id": "pi", "target": "x.service"}).status_code, 403)

    def test_token_scope_permissions_registered(self):
        permissions = self.app.config["TOKEN_SCOPE_PERMISSIONS"]
        for endpoint, permission in {
            "api_v1_applications": "view",
            "api_v1_applications_create": "config.write",
            "api_v1_application": "view",
            "api_v1_application_update": "config.write",
            "api_v1_application_archive": "config.write",
            "api_v1_application_restore": "config.write",
            "api_v1_application_instances": "view",
            "api_v1_application_instances_create": "config.write",
            "api_v1_application_instance": "config.write",
            "api_v1_application_instance_delete": "config.write",
            "api_v1_application_health": "view",
        }.items():
            self.assertEqual(permissions[endpoint], permission)

    # -- CRUD round trips ---------------------------------------------------------
    def test_admin_create_get_update(self):
        self._login("bob")
        application = self._create_application(
            slug="desk", lifecycle="active", criticality="high",
            version="1.2.3", owner="jason", tags=["kiosk"])
        self.assertEqual(application["id"], "desk")
        self.assertEqual(application["criticality"], "high")

        detail = self.client.get("/api/v1/applications/desk")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["application"]["lifecycle"], "active")

        updated = self._patch("/api/v1/applications/desk", {"description": "new"})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["application"]["description"], "new")

        self.assertEqual(self.client.get("/api/v1/applications/nope").status_code, 404)

    def test_admin_cannot_bypass_validation(self):
        self._login("bob")
        self.assertEqual(self._post("/api/v1/applications", {}).status_code, 400)
        self._create_application(slug="desk")
        self.assertEqual(
            self._post("/api/v1/applications", {"name": "Desk", "slug": "desk"}).status_code,
            409)
        self.assertEqual(
            self._post("/api/v1/applications", {"name": "X", "lifecycle": "archived"}).status_code,
            400)
        self.assertEqual(
            self._post("/api/v1/applications",
                       {"name": "Y", "strategy": {"strategy": "bogus"}}).status_code, 400)

    def test_archive_read_only_restore(self):
        self._login("bob")
        self._create_application(slug="desk")
        archived = self._post("/api/v1/applications/desk/archive",
                              {"reason": "retiring"})
        self.assertEqual(archived.status_code, 200)
        self.assertEqual(archived.get_json()["application"]["lifecycle"], "archived")
        # Archived: writes are 409, but the row still reads.
        self.assertEqual(self._patch("/api/v1/applications/desk",
                                     {"name": "nope"}).status_code, 409)
        self.assertEqual(self.client.get("/api/v1/applications/desk").status_code, 200)
        self.assertEqual(
            self._post("/api/v1/applications/desk/restore", {}).status_code, 200)
        self.assertEqual(
            self.client.get("/api/v1/applications/desk").get_json()["application"]["lifecycle"],
            "active")
        self.assertEqual(self._post("/api/v1/applications/desk/restore", {}).status_code, 409)

    def test_instances_crud(self):
        self._login("bob")
        self._create_application(slug="desk")
        added = self._post("/api/v1/applications/desk/instances",
                           {"device_id": "pi", "mechanism": "systemd",
                            "target": "desk.service"})
        self.assertEqual(added.status_code, 201)
        instance_id = added.get_json()["instance"]["instance_id"]
        # The roster (the published state cache) knows "pi".
        self.assertEqual(
            self._post("/api/v1/applications/desk/instances",
                       {"device_id": "ghost", "target": "x.service"}).status_code, 400)
        self.assertEqual(
            self._post("/api/v1/applications/desk/instances",
                       {"device_id": "pi", "mechanism": "systemd",
                        "target": "desk.service"}).status_code, 409)
        listed = self.client.get("/api/v1/applications/desk/instances")
        self.assertEqual(len(listed.get_json()["instances"]), 1)
        updated = self._patch(f"/api/v1/applications/desk/instances/{instance_id}",
                              {"critical": True})
        self.assertEqual(updated.status_code, 200)
        self.assertTrue(updated.get_json()["instance"]["critical"])
        removed = self._delete(f"/api/v1/applications/desk/instances/{instance_id}")
        self.assertEqual(removed.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/applications/desk/instances")
                         .get_json()["instances"], [])

    def test_health_endpoint_reads_poll_persisted_state(self):
        self._login("bob")
        self._create_application(slug="desk")
        self._post("/api/v1/applications/desk/instances",
                   {"device_id": "pi", "mechanism": "systemd",
                    "target": "desk.service"})
        service = self.app.extensions["pinoc_applications"]
        service.tick()  # the poll would do this (wall clock); the endpoint must only read
        response = self.client.get("/api/v1/applications/desk/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["health"], "healthy")
        self.assertEqual(payload["instances"][0]["health"], "healthy")
        self.assertEqual(len(payload["snapshots"]), 1)
        self.assertEqual(payload["snapshots"][0]["strategy"], "service")

    # -- redaction ---------------------------------------------------------------
    def test_outputs_are_redacted(self):
        self._login("bob")
        self._post("/api/v1/applications", {
            "name": "Desk", "slug": "desk",
            "endpoints": ["https://example.com/api?token=supersecretvalue&x=1"],
            "strategy": {"strategy": "http",
                         "url": "https://example.com/health?token=supersecretvalue"},
        })
        text = self.client.get("/api/v1/applications").get_data(as_text=True)
        self.assertNotIn("supersecretvalue", text)
        self.assertIn("token=[REDACTED]", text)
        detail = self.client.get("/api/v1/applications/desk").get_data(as_text=True)
        self.assertNotIn("supersecretvalue", detail)

    # -- page ----------------------------------------------------------------------
    def test_applications_page_renders(self):
        self._login("bob")
        page = self.client.get("/applications")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Applications", page.data)
        self.assertIn(b"PiNOC.applications()", page.data)


# ---------------------------------------------------------------------------
# configuration validation
# ---------------------------------------------------------------------------

class TestConfigValidation(unittest.TestCase):
    def test_valid_section_accepted(self):
        validate_applications({"applications": {
            "enabled": True, "poll_seconds": 60, "http_timeout_seconds": 10,
            "tcp_timeout_seconds": 5, "freshness_seconds": 300,
            "snapshot_retention_days": 35,
            "command_templates": {"ok": {"command": "true", "timeout_seconds": 10}},
        }})

    def test_absent_section_is_valid(self):
        validate_applications({})
        validate_applications({"applications": None})

    def test_invalid_values_rejected(self):
        cases = [
            {"applications": "on"},
            {"applications": {"enabled": "yes"}},
            {"applications": {"poll_seconds": 4}},
            {"applications": {"poll_seconds": 86401}},
            {"applications": {"poll_seconds": "fast"}},
            {"applications": {"http_timeout_seconds": 0}},
            {"applications": {"tcp_timeout_seconds": 301}},
            {"applications": {"freshness_seconds": 9}},
            {"applications": {"snapshot_retention_days": 1.5}},
            {"applications": {"snapshot_retention_days": 3651}},
            {"applications": {"command_templates": ["true"]}},
            {"applications": {"command_templates": {"bad name": {"command": "true"}}}},
            {"applications": {"command_templates": {"ok": "true"}}},
            {"applications": {"command_templates": {"ok": {"command": ""}}}},
            {"applications": {"command_templates": {"ok": {"command": "a" * 513}}}},
            {"applications": {"command_templates": {"ok": {"command": "tr\x00e"}}}},
            {"applications": {"command_templates":
                {"ok": {"command": "true", "timeout_seconds": 0}}}},
            {"applications": {"command_templates":
                {"ok": {"command": "true", "timeout_seconds": 301}}}},
        ]
        for value in cases:
            with self.assertRaises(ValueError, msg=value):
                validate_applications(value)

    def test_too_many_templates_rejected(self):
        value = {"applications": {"command_templates":
                                  {f"t{i}": {"command": "true"} for i in range(101)}}}
        with self.assertRaises(ValueError):
            validate_applications(value)

    def test_validate_config_runs_application_validation(self):
        from pinoc.config_store import validate_config
        base = {"devices": [], "polling": {"fleet_seconds": 10}}
        with tempfile.TemporaryDirectory() as tmp:
            # An empty base dir has no devices.json to pull in; the
            # applications section is validated alongside the rest.
            self.assertEqual(validate_config(
                {**base, "applications": {"poll_seconds": 60}}, Path(tmp)),
                {**base, "applications": {"poll_seconds": 60}})
            with self.assertRaises(ValueError):
                validate_config({**base, "applications": {"poll_seconds": 1}}, Path(tmp))


# ---------------------------------------------------------------------------
# fleet collector __APPS__ section
# ---------------------------------------------------------------------------

class TestCollectorApps(unittest.TestCase):
    def _device(self, **overrides):
        values = dict(id="pi", hostname="pi", friendly_name="Pi",
                      address="192.168.1.10", collection_method="ssh",
                      monitored_services=["ssh"], critical_services=["ssh"])
        values.update(overrides)
        return DeviceConfig(**values)

    def _collector(self):
        return FleetCollector([self._device()],
                              runner=lambda *args, **kwargs: None, timeout=1)

    # -- argv construction ------------------------------------------------------
    def test_command_includes_apps_section_when_due(self):
        collector = self._collector()
        args = collector._command(self._device(),
                                  apps=["systemd|desk.service", "pm2|desk-web"])
        self.assertIn("__APPS__:systemd|desk.service,pm2|desk-web", args)
        # The systemd implementation also rides the single systemctl show call...
        self.assertIn("desk.service", args)
        # ...while non-systemd implementations only go to the due-gated section.
        self.assertNotIn("desk-web", [a for a in args if not a.startswith("__")])

    def test_command_omits_apps_section_when_not_due(self):
        collector = self._collector()
        args = collector._command(self._device())
        self.assertFalse(any(a.startswith("__APPS__") for a in args))

    def test_unsafe_systemd_names_stay_out_of_systemctl_show(self):
        collector = self._collector()
        args = collector._command(self._device(),
                                  apps=["systemd|bad;rm", "systemd|ok.service"])
        self.assertNotIn("bad;rm", args)
        self.assertIn("ok.service", args)
        self.assertIn("__APPS__:systemd|bad;rm,systemd|ok.service", args)

    def test_specs_capped_at_fifty(self):
        collector = self._collector()
        specs = [f"process|unit-{i}" for i in range(60)]
        args = collector._command(self._device(), apps=specs)
        sentinel = next(a for a in args if a.startswith("__APPS__:"))
        self.assertEqual(len(sentinel.split(":")[1].split(",")), 50)

    # -- parsing ------------------------------------------------------------------
    def test_parse_app_checks(self):
        entries = parse_app_checks("desk-web|pm2|running\nother|process|stopped\n"
                                   "incomplete|pm2\n")
        self.assertEqual(entries, [
            {"name": "desk-web", "kind": "pm2", "status": "running"},
            {"name": "other", "kind": "process", "status": "stopped"},
        ])
        big = parse_app_checks("\n".join(f"n{i}|process|running" for i in range(60)))
        self.assertEqual(len(big), 50)
        self.assertEqual(parse_app_checks(""), [])

    # -- due gating in collect_device ------------------------------------------------
    def test_collect_device_due_gates_app_checks(self):
        device = self._device()
        seen = []

        def runner(args, **kwargs):
            seen.append(list(args))
            return completed(APPS_OUTPUT)

        collector = FleetCollector([device], runner=runner, timeout=1,
                                   apps_check_seconds=300)
        # Calling collect_device directly skips collect()'s spec refresh, so
        # seed the due-gating input the way the real wiring would.
        collector.app_specs = {"pi": ["desk-web|pm2"]}
        first = collector.collect_device(device)
        self.assertTrue(any(a.startswith("__APPS__") for a in seen[-1]))
        self.assertEqual(first.app_checks,
                         [{"name": "desk-web", "kind": "pm2", "status": "running"}])
        # Not due: the argument disappears, but the last real checks persist.
        collector._last_apps_check[device.id] = time.monotonic()
        second = collector.collect_device(device)
        self.assertFalse(any(a.startswith("__APPS__") for a in seen[-1]))
        self.assertEqual(second.app_checks, first.app_checks)
        # Due again after the cadence: re-reported.
        collector._last_apps_check[device.id] = time.monotonic() - 301
        third = collector.collect_device(device)
        self.assertTrue(any(a.startswith("__APPS__") for a in seen[-1]))
        self.assertEqual(third.app_checks, first.app_checks)

    # -- the spec hook in collect() ---------------------------------------------------
    def test_collect_refreshes_application_specs(self):
        collector = self._collector()
        collector.application_specs = lambda: {"pi": ["systemd|desk.service"]}
        collector.collect()
        self.assertEqual(collector.app_specs, {"pi": ["systemd|desk.service"]})

    def test_collect_keeps_last_good_specs_when_source_fails(self):
        collector = self._collector()
        collector.app_specs = {"pi": ["systemd|desk.service"]}

        def broken():
            raise RuntimeError("database exploded")

        collector.application_specs = broken
        collector.collect()  # must not raise, must keep the last good specs
        self.assertEqual(collector.app_specs, {"pi": ["systemd|desk.service"]})

    def test_collect_without_hook_keeps_specs(self):
        collector = self._collector()
        collector.app_specs = {"pi": ["pm2|desk-web"]}
        collector.collect()
        self.assertEqual(collector.app_specs, {"pi": ["pm2|desk-web"]})

    # -- the full loop: service -> collector -> state -> strategy --------------------
    def test_full_loop_specs_output_and_process_strategy(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = _RecordingHistory()
        self.state = PiNOCState()
        self.service = ApplicationService(self.db, state=self.state,
                                          history=self.history)
        application = self.service.create({"name": "Desk", "slug": "desk"})
        self.service.add_instance(application["id"], {"device_id": "pi",
                                                      "mechanism": "pm2",
                                                      "target": "desk-web"})
        collector = FleetCollector([self._device()],
                                   runner=lambda *args, **kwargs: completed(APPS_OUTPUT),
                                   timeout=1, apps_check_seconds=300)
        collector.application_specs = self.service.device_app_specs
        results = collector.collect()
        self.assertEqual(len(results), 1)
        collected = results[0]
        self.assertEqual(collected.app_checks,
                         [{"name": "desk-web", "kind": "pm2", "status": "running"}])
        self.state.publish(results, replace=True)
        self.service.tick(now=NOW)
        instance = self.service.instances(application["id"])[0]
        # The zero-config pm2 default (process name) resolved against the
        # __APPS__ section the host re-reported.
        self.assertEqual(instance["health"], "healthy")


# ---------------------------------------------------------------------------
# history retention
# ---------------------------------------------------------------------------

class TestHistoryRetention(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.now = datetime.now(UTC)
        old = (self.now - timedelta(days=2)).isoformat()
        self.db.execute(
            "INSERT INTO application_health_snapshots(app_slug,instance_id,device_id,health,"
            "reasons_json,strategy,source,observed_at,checked_at,ttl_seconds,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("desk", 1, "pi", "healthy", "[]", "service", "strategy",
             old, old, 300, 1.0))
        self.db.execute(
            "INSERT INTO application_health_snapshots(app_slug,instance_id,device_id,health,"
            "reasons_json,strategy,source,observed_at,checked_at,ttl_seconds,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("desk", 1, "pi", "warning", "[]", "service", "strategy",
             self.now.isoformat(), self.now.isoformat(), 300, 1.0))

    def test_old_snapshots_are_pruned(self):
        history = HistoryManager(self.db, {},
                                 applications={"snapshot_retention_days": 1})
        history.maintenance(now=self.now)
        rows = self.db.rows("SELECT checked_at FROM application_health_snapshots")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["checked_at"], self.now.isoformat())

    def test_default_retention_is_long(self):
        history = HistoryManager(self.db, {})  # 35-day default
        history.maintenance(now=self.now)
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM application_health_snapshots"), 2)


if __name__ == "__main__":
    unittest.main()
