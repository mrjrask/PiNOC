"""Coverage for the allowlisted disk-rescue actions (apt, logs, journal, cache)."""
import subprocess
import tempfile
import time
import unittest

from pinoc.actions import RESCUE_ACTIONS, ActionDispatcher, ActionError, valid_log_path
from pinoc.database import Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.playbooks import _clean_entry, validate_playbooks
from pinoc.security import SecurityManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app


class Coordinator:
    def __init__(self):
        self.refreshed = []

    def refresh_device(self, d):
        self.refreshed.append(d)

    def refresh(self):
        self.refreshed.append("all")


ALL_RESCUES = ["apt.clean", "apt.autoremove", "logs.truncate", "journal.vacuum", "cache.drop"]


def make_device(**overrides) -> DeviceState:
    values = dict(id="pi", hostname="pi", friendly_name="Pi", online=True, address="host",
                  collection_method="ssh", ssh_user="pi", ssh_port=22,
                  manageable_services=["demo.service"],
                  allowed_actions=["package.check"],
                  important_paths=["/srv/jonah"])
    values.update(overrides)
    return DeviceState(**values)


def fixture(tmp_path, role="operator", enabled=True, device=None):
    db = Database(f"{tmp_path}/db.sqlite")
    assert db.initialize()
    history = HistoryManager(db, {})
    state = PiNOCState()
    state.publish([device or make_device(allowed_actions=ALL_RESCUES)], replace=True)
    app = create_app(state, {"TESTING": True, "AUTH_ENABLED": enabled,
                             "SECRET_KEY": "test-secret", "DATABASE": db},
                     history, Coordinator())
    return app, db, state


def running_dispatcher(db, state, runner=None):
    return ActionDispatcher(db, state, Coordinator(), runner=runner or (lambda *a, **k: None))


def wait_for(dispatcher, job, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        row = dispatcher.get(job["job_id"])
        if row["status"] not in ("queued", "running"):
            return row
        time.sleep(0.01)
    raise AssertionError("action job did not finish")


def fake_runner(table):
    """table: list of (argv_sublist, stdout, stderr, code); first match wins."""
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        for match, stdout, stderr, code in table:
            if all(piece in args for piece in match):
                return subprocess.CompletedProcess(args, code, stdout, stderr)
        return subprocess.CompletedProcess(args, 0, "", "")

    return runner, calls


DF_LOW = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 152241344 140000000 1000 93% /\n"
DF_HIGH = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 152241344 138000000 30000 90% /\n"


def has_argv(calls, tail):
    """True when some recorded (possibly ssh-wrapped) argv ends with tail."""
    tail = list(tail)
    return any(list(args)[-len(tail):] == tail for args, _ in calls)


class RegistryTest(unittest.TestCase):
    def test_definitions(self):
        self.assertEqual(RESCUE_ACTIONS, {"apt.clean", "apt.autoremove", "logs.truncate",
                                          "journal.vacuum", "cache.drop"})
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/db.sqlite")
            db.initialize()
            dispatcher = ActionDispatcher(db, PiNOCState())
            try:
                for action in ALL_RESCUES:
                    definition = dispatcher.definition(action)
                    self.assertEqual(definition.permission, "actions.execute")
                self.assertEqual(dispatcher.definition("apt.clean").confirmation, "simple")
                self.assertEqual(dispatcher.definition("apt.autoremove").confirmation, "simple")
                for action in ("logs.truncate", "journal.vacuum", "cache.drop"):
                    self.assertEqual(dispatcher.definition(action).confirmation, "strong")
                with self.assertRaises(ActionError):
                    dispatcher.definition("apt.reinstall")
            finally:
                dispatcher.stop()


class ValidationTest(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tmp = tmp
            db = Database(f"{tmp}/db.sqlite")
            self.assertTrue(db.initialize())
            self.state = PiNOCState()
            self.state.publish([make_device(allowed_actions=ALL_RESCUES)], replace=True)
            self.dispatcher = ActionDispatcher(db, self.state)
            self.addCleanup(self.dispatcher.stop)

    def test_default_off_per_device(self):
        self.state.publish([make_device(allowed_actions=["package.check"])], replace=True)
        for action in ALL_RESCUES:
            with self.assertRaises(ActionError) as ctx:
                self.dispatcher.validate(action, "pi")
            self.assertIn("not approved", str(ctx.exception))

    def test_allowed_device_passes(self):
        for action in ALL_RESCUES:
            self.dispatcher.validate(action, "pi")

    def test_offline_device_rejected(self):
        self.state.publish([make_device(allowed_actions=ALL_RESCUES, online=False, health="offline")], replace=True)
        with self.assertRaises(ActionError):
            self.dispatcher.validate("apt.clean", "pi")

    def test_log_target_rules(self):
        self.dispatcher.validate("logs.truncate", "pi", "/var/log/syslog")
        self.dispatcher.validate("logs.truncate", "pi", "/srv/jonah/app.log")
        for bad in ("/etc/passwd", "/var/log/../../etc/passwd", "relative.log",
                    "/var/log//syslog", "/srv/jonah/../../etc/shadow"):
            with self.assertRaises(ActionError) as ctx:
                self.dispatcher.validate("logs.truncate", "pi", bad)
            self.assertIn("log path", str(ctx.exception))

    def test_journal_spec_rules(self):
        for good in ("time:7d", "size:100M", "size:1G", "time:24h"):
            self.dispatcher.validate("journal.vacuum", "pi", good)
        for bad in ("banana", "size:123456M", "time:", "size:1.5M", "rm -rf /"):
            with self.assertRaises(ActionError):
                self.dispatcher.validate("journal.vacuum", "pi", bad)

    def test_valid_log_path_helper(self):
        self.assertTrue(valid_log_path("/var/log/syslog"))
        self.assertTrue(valid_log_path("/var/log/journal/abc/app.log.2.gz"))
        self.assertTrue(valid_log_path("/srv/jonah/nested/deep.log", ["/srv/jonah"]))
        self.assertFalse(valid_log_path("/var/log/../etc/passwd"))
        self.assertFalse(valid_log_path("var/log/syslog"))
        self.assertFalse(valid_log_path("/tmp/data/secret.log", ["/srv/jonah"]))
        self.assertFalse(valid_log_path("x" * 300))
        self.assertFalse(valid_log_path(None))

    def test_important_paths_cannot_target_a_non_log_file(self):
        # important_paths is shared with the read-only-mount health check,
        # so a broadly declared entry must not let logs.truncate zero out
        # an arbitrary file just because it sits under that prefix.
        self.assertFalse(valid_log_path("/etc/passwd", ["/etc"]))
        self.assertFalse(valid_log_path("/srv/jonah/config.json", ["/srv/jonah"]))
        self.assertFalse(valid_log_path("/srv/jonah/nested/id_rsa", ["/srv/jonah"]))
        self.assertTrue(valid_log_path("/srv/jonah/nested/app.log", ["/srv/jonah"]))
        self.assertTrue(valid_log_path("/srv/jonah/syslog", ["/srv/jonah"]))


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        # Kept alive past _run() so tests can still query the database.
        self._tmp = None

    def _run(self, action, target=None, table=None, runner=None, **device_kwargs):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = self._tmp.name
        db = Database(f"{tmp}/db.sqlite")
        self.assertTrue(db.initialize())
        if runner is None:
            runner, calls = fake_runner(table or [])
        else:
            calls = runner["calls"]
            runner = runner["fn"]
        state = PiNOCState()
        state.publish([make_device(allowed_actions=ALL_RESCUES, **device_kwargs)], replace=True)
        dispatcher = ActionDispatcher(db, state, Coordinator(), runner=runner)
        self.addCleanup(dispatcher.stop)
        job = dispatcher.enqueue(action, "pi", target, "op", "operator")
        row = wait_for(dispatcher, job)
        return row, calls, db

    def test_apt_clean_reports_space_freed(self):
        calls = []
        df_seen = [0]

        def stateful(args, **kwargs):
            calls.append((args, kwargs))
            if "df" in args:
                df_seen[0] += 1
                return subprocess.CompletedProcess(args, 0, DF_HIGH if df_seen[0] > 1 else DF_LOW, "")
            if "apt-get" in args:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        row, calls, db = self._run("apt.clean", runner={"fn": stateful, "calls": calls})
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("freed", row["summary"])
        self.assertIn("MiB", row["summary"])
        self.assertTrue(has_argv(calls, ["sudo", "-n", "apt-get", "clean"]))
        for _, kwargs in calls:
            self.assertNotIn("shell", kwargs)
        # The audit insert follows the job-status update; poll briefly.
        end, count = time.time() + 2, None
        while time.time() < end:
            count = db.scalar("SELECT COUNT(*) FROM audit_records WHERE action='apt.clean'")
            if count:
                break
            time.sleep(0.01)
        # Two audit rows exist by design (enqueue + execution); only require at
        # least one so a slow worker cannot flake the test.
        self.assertGreaterEqual(count or 0, 1)

    def test_apt_autoremove_is_simulation_only(self):
        row, calls, _ = self._run("apt.autoremove", table=[
            (["apt-get", "--just-print", "-y", "autoremove"],
             "Reading database...\nRemv libobsolete1\nRemv libobsolete2\n", "", 0),
        ])
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("2 package(s) would be removed", row["summary"])
        self.assertIn("no changes made", row["summary"])
        # Every call touching autoremove must stay in simulation mode.
        for args, _ in calls:
            if "autoremove" in " ".join(args):
                self.assertIn("--just-print", args)

    def test_apt_failure_is_recorded_with_redacted_error(self):
        row, _, _ = self._run("apt.clean", table=[
            (["df"], DF_LOW, "", 0),
            (["apt-get", "clean"], "", "E: could not get lock; password=supersecret", 100),
        ])
        self.assertEqual(row["status"], "failed")
        self.assertIn("100", row["summary"])
        self.assertIn("lock", row["error"])
        self.assertNotIn("supersecret", row["error"])

    def test_logs_truncate_explicit_target(self):
        row, calls, _ = self._run("logs.truncate", "/var/log/syslog", table=[
            (["stat", "-c", "%s", "/var/log/syslog"], "10485760\n", "", 0),
            (["truncate", "-s", "0", "/var/log/syslog"], "", "", 0),
        ])
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(row["target"], "/var/log/syslog")
        self.assertIn("10 MiB", row["summary"])
        self.assertTrue(has_argv(calls, ["sudo", "-n", "truncate", "-s", "0", "/var/log/syslog"]))

    def test_logs_truncate_auto_picks_largest(self):
        du = ("12\t/var/log\n2048\t/var/log/syslog\n4096\t/var/log/app.log.1.gz\n"
              "300\t/var/log/journal\n64\t/var/log/wtmp\n")
        row, calls, _ = self._run("logs.truncate", None, table=[
            (["du"], du, "", 0),
            (["truncate", "-s", "0", "/var/log/app.log.1.gz"], "", "", 0),
        ])
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("app.log.1.gz", row["summary"])
        self.assertIn("4 MiB", row["summary"])
        self.assertTrue(has_argv(calls, ["sudo", "-n", "du", "-ak", "/var/log"]))

    def _journal_runner(self, before, after, flag, calls):
        seen = [0]

        def fn(args, **kwargs):
            calls.append((args, kwargs))
            if "--disk-usage" in args:
                seen[0] += 1
                return subprocess.CompletedProcess(args, 0, f"Logs take {before if seen[0] == 1 else after} in the journal.\n", "")
            if flag in args:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        return {"fn": fn, "calls": calls}

    def test_journal_vacuum_default_time(self):
        calls = []
        row, calls, _ = self._run("journal.vacuum", None,
                                  runner=self._journal_runner("25.3M", "8.1M", "--vacuum-time=7d", calls))
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("25.3M", row["summary"])
        self.assertIn("8.1M", row["summary"])
        self.assertTrue(has_argv(calls, ["sudo", "-n", "journalctl", "--vacuum-time=7d"]))

    def test_journal_vacuum_size_spec(self):
        calls = []
        row, calls, _ = self._run("journal.vacuum", "size:100M",
                                  runner=self._journal_runner("250M", "99.5M", "--vacuum-size=100M", calls))
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(row["summary"], "journal vacuumed (size:100M); 250M → 99.5M")
        self.assertTrue(has_argv(calls, ["sudo", "-n", "journalctl", "--vacuum-size=100M"]))

    def test_cache_drop_uses_tee_stdin_not_shell(self):
        calls = []
        seen = [0]

        def stateful(args, **kwargs):
            calls.append((args, kwargs))
            if "/proc/meminfo" in args:
                seen[0] += 1
                available = 900000 if seen[0] > 1 else 500000
                return subprocess.CompletedProcess(args, 0, f"MemTotal:       8000000 kB\nMemAvailable: {available:>6} kB\n", "")
            if "tee" in args:
                return subprocess.CompletedProcess(args, 0, "3\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        row, calls, _ = self._run("cache.drop", runner={"fn": stateful, "calls": calls})
        self.assertEqual(row["status"], "succeeded")
        self.assertIn("MemAvailable", row["summary"])
        tee = [c for c in calls if "tee" in c[0]]
        self.assertEqual(tee[0][1].get("input"), "3\n")
        for args, kwargs in calls:
            self.assertNotIn("shell", kwargs)

    def test_ssh_wrapping_preserved(self):
        row, calls, _ = self._run("apt.clean", table=[
            (["df"], DF_LOW, "", 0),
            (["apt-get", "clean"], "", "", 0),
        ])
        for args, _ in calls:
            self.assertEqual(args[0], "ssh")
            self.assertIn("BatchMode=yes", args)
            self.assertIn("pi@host", args)


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app, self.db, self.state = fixture(
            self._tmp.name, role="operator",
            device=make_device(allowed_actions=ALL_RESCUES))
        # Never shell out from the web tests: jobs complete instantly.
        self.app.extensions["pinoc_actions"].runner = lambda args, **kw: subprocess.CompletedProcess(args, 0, "", "")
        self.security: SecurityManager = self.app.extensions["pinoc_security"]
        self.security.create_user("op", "correct horse battery", "operator")
        self.security.create_user("watcher", "correct horse battery", "viewer")
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.extensions["pinoc_actions"].stop()
        self._tmp.cleanup()

    def _login(self, username):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post("/login", data={"username": username,
                                                "password": "correct horse battery",
                                                "csrf_token": csrf})

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _post(self, path, body=None):
        return self.client.post(path, json=body or {}, headers={"X-CSRF-Token": self._csrf()})

    def test_operator_can_queue_rescues(self):
        assert self._login("op").status_code == 302
        dispatcher = self.app.extensions["pinoc_actions"]
        for path, body in (
            ("/api/devices/pi/actions/apt-clean", {}),
            ("/api/devices/pi/actions/apt-autoremove", {}),
            ("/api/devices/pi/actions/logs-truncate", {"target": "/var/log/syslog"}),
            ("/api/devices/pi/actions/journal-vacuum", {"target": "size:100M"}),
            ("/api/devices/pi/actions/cache-drop", {}),
        ):
            response = self._post(path, body)
            self.assertEqual(response.status_code, 202, path)
            job = response.get_json()
            self.assertIn("job_id", job)
            # Drain the job so the per-device conflict lock frees for the next.
            end = time.time() + 5
            while dispatcher.get(job["job_id"])["status"] in ("queued", "running") and time.time() < end:
                time.sleep(0.01)
        # The body target lands on the job and the audit trail.
        jobs = self.db.rows("SELECT * FROM action_jobs")
        self.assertIn("/var/log/syslog", [x["target"] for x in jobs])
        self.assertGreaterEqual(self.db.scalar("SELECT COUNT(*) FROM audit_records"), len(jobs))

    def test_viewer_is_denied(self):
        assert self._login("watcher").status_code == 302
        self.assertEqual(self._post("/api/devices/pi/actions/apt-clean").status_code, 403)

    def test_unauthenticated_is_401(self):
        self.assertEqual(self.client.post("/api/devices/pi/actions/apt-clean").status_code, 401)

    def test_invalid_target_is_400(self):
        assert self._login("op").status_code == 302
        response = self._post("/api/devices/pi/actions/logs-truncate", {"target": "/etc/passwd"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("log path", response.get_json()["error"])
        response = self._post("/api/devices/pi/actions/journal-vacuum", {"target": "banana"})
        self.assertEqual(response.status_code, 400)

    def test_token_scopes(self):
        execute_token = self.security.create_token("op", ["execute:safe_actions"])
        read_token = self.security.create_token("op", ["read:fleet"])
        ok = self.client.post("/api/devices/pi/actions/apt-clean",
                              headers={"Authorization": "Bearer " + execute_token})
        self.assertEqual(ok.status_code, 202)
        denied = self.client.post("/api/devices/pi/actions/apt-clean",
                                  headers={"Authorization": "Bearer " + read_token})
        self.assertEqual(denied.status_code, 403)

    def test_unallowlisted_device_denied(self):
        assert self._login("op").status_code == 302
        self.state.publish([make_device(allowed_actions=["package.check"])], replace=True)
        self.assertEqual(self._post("/api/devices/pi/actions/apt-clean").status_code, 400)
        self.assertEqual(self._post("/api/devices/pi/actions/package-check").status_code, 202)


class PlaybookTest(unittest.TestCase):
    def test_rescue_actions_pass_playbook_validation(self):
        entry = {"id": "disk-full", "alert_type": "critical_disk_usage", "title": "Disk full",
                 "markdown": "Free space first.",
                 "actions": ["apt.clean", "apt.autoremove", "logs.truncate",
                             "journal.vacuum", "cache.drop"]}
        clean, error = _clean_entry(entry)
        self.assertIsNone(error)
        self.assertEqual(clean["actions"], entry["actions"])
        validate_playbooks([entry])  # must not raise
        with self.assertRaises(ValueError):
            validate_playbooks([{**entry, "id": "bad", "actions": ["apt.upgrade"]}])

    def test_rescue_actions_pass_with_known_registry(self):
        entry = {"id": "r2", "alert_type": "high_disk_usage", "title": "T", "markdown": "x",
                 "actions": ["apt.clean"]}
        clean, error = _clean_entry(entry, known_actions=list(RESCUE_ACTIONS) + ["package.check"])
        self.assertIsNone(error)
        self.assertEqual(clean["actions"], ["apt.clean"])


if __name__ == "__main__":
    unittest.main()
