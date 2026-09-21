"""Coverage for one-file backup/restore bundles and scheduled remote backups."""
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from pinoc.backup import (BackupError, BackupService, build_bundle, env_manifest,
                          required_env_keys, restore_bundle, verify_bundle)
from pinoc.config_store import validate_backups, validate_config
from pinoc.database import Database, SCHEMA_VERSION
from pinoc.history import HistoryManager
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

import pinoc.backup as backup_module

CONFIG = {"authentication": {"enabled": True}, "devices_file": "config/devices.json"}
ENV = ("# comment line\nPINOC_SECRET_KEY=topsecretvalue\n"
       "export PINOC_WEB_PORT=9999\n\nCM5_SSH_PASS=another-value\n")


def make_instance(root: Path) -> Path:
    root = Path(root)
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text(json.dumps(CONFIG))
    (root / "config" / "devices.json").write_text('{"devices": [{"id": "pi"}]}')
    (root / ".env").write_text(ENV)
    return root


def make_db(path: str) -> Database:
    db = Database(path)
    assert db.initialize()
    db.execute("INSERT INTO device_metrics(timestamp, device_id, cpu_percent) VALUES(?,?,?)",
               ("2025-01-01T00:00:00+00:00", "pi", 12.5))
    return db


class EnvManifestTest(unittest.TestCase):
    def test_names_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(ENV)
            self.assertEqual(env_manifest(path),
                             ["PINOC_SECRET_KEY", "PINOC_WEB_PORT", "CM5_SSH_PASS"])

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(env_manifest(Path(tmp) / "nope"), [])


class BuildVerifyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.instance = make_instance(self._tmp.name)
        self.db = make_db(f"{self._tmp.name}/db.sqlite")
        self.addCleanup(self._tmp.cleanup)

    def _bundle(self, *args, **kwargs):
        return build_bundle(self.instance, Path(self._tmp.name) / "bundle.tar",
                            self.db, *args, **kwargs)

    def test_bundle_members_and_manifest(self):
        metadata = self._bundle()
        self.assertTrue(Path(metadata["path"]).exists())
        self.assertEqual(metadata["signature_algorithm"], "SHA-256")
        _, members = backup_module.read_bundle(Path(metadata["path"]))
        self.assertEqual(sorted(members), sorted(
            ["config.json", "config/devices.json", "env-manifest.txt",
             "pinoc.db", "bundle.json", "bundle.sig"]))
        manifest = members["env-manifest.txt"].decode()
        self.assertIn("PINOC_SECRET_KEY", manifest)
        self.assertNotIn("topsecretvalue", manifest)
        self.assertNotIn("another-value", manifest)
        self.assertNotIn("9999", manifest)
        self.assertIn('"pi"', members["config/devices.json"].decode())
        # Secret values from .env must not appear in any bundle member.
        for name, data in members.items():
            self.assertNotIn("topsecretvalue", data.decode("utf-8", "replace"))
            self.assertNotIn("another-value", data.decode("utf-8", "replace"))

    def test_build_bundle_never_uses_the_insecure_mktemp(self):
        # tempfile.mktemp() only returns a name; it never creates the file,
        # leaving a window for another local process to create or symlink
        # it first. The online-backup scratch file must use mkstemp()
        # instead, which creates it atomically.
        with mock.patch("tempfile.mktemp", side_effect=AssertionError(
                "tempfile.mktemp() must not be used for the backup scratch file")):
            metadata = self._bundle()
        _, members = backup_module.read_bundle(Path(metadata["path"]))
        # The database backup must still be a valid copy containing the row.
        restored = f"{self._tmp.name}/probe.sqlite"
        Path(restored).write_bytes(members["pinoc.db"])
        probe = Database(restored)
        self.assertTrue(probe.initialize())
        self.assertEqual(probe.scalar("SELECT COUNT(*) FROM device_metrics"), 1)

    def test_verify_unsigned(self):
        metadata = self._bundle()
        ok, md, issues = verify_bundle(Path(metadata["path"]))
        self.assertTrue(ok, issues)
        self.assertEqual(md["schema_version"], SCHEMA_VERSION)
        self.assertEqual(md["config_sha256"], metadata["config_sha256"])

    def test_verify_hmac(self):
        metadata = self._bundle(signing_key="k1")
        self.assertEqual(metadata["signature_algorithm"], "HMAC-SHA256")
        ok, _, issues = verify_bundle(Path(metadata["path"]), signing_key="k1")
        self.assertTrue(ok, issues)
        ok, _, issues = verify_bundle(Path(metadata["path"]), signing_key="wrong")
        self.assertFalse(ok)
        self.assertTrue(any("signature" in i for i in issues))
        ok, _, issues = verify_bundle(Path(metadata["path"]))
        self.assertFalse(ok)
        self.assertTrue(any("signing key is required" in i for i in issues))

    def test_tampered_bundle_fails(self):
        metadata = self._bundle(signing_key="k1")
        path = Path(metadata["path"])
        members = backup_module.read_bundle(path)[1]
        members["config.json"] = json.dumps({**CONFIG, "web_port": 1}).encode()
        import io, tarfile
        with tarfile.open(path, "w") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                import io as _io
                tar.addfile(info, _io.BytesIO(data))
        ok, _, issues = verify_bundle(path, signing_key="k1")
        self.assertFalse(ok)
        self.assertTrue(any("digest mismatch" in i or "signature" in i for i in issues))

    def test_read_bundle_rejects_an_oversized_member(self):
        # build_bundle() enforces MAX_CONFIG_BYTES/MAX_DATABASE_BYTES on
        # write, but nothing enforced the same limits on read before any
        # trust decision (signature/digest) is made.
        import io, tarfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.tar"
            oversized = b"x" * (backup_module.MAX_CONFIG_BYTES + 1)
            members = {"config.json": b"{}", "env-manifest.txt": oversized,
                      "pinoc.db": b"db", "bundle.json": json.dumps({"format": "pinoc-bundle"}).encode()}
            with tarfile.open(path, "w") as tar:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))

            called_for = []
            original_extractfile = tarfile.TarFile.extractfile
            def spy_extractfile(self, member):
                called_for.append(member.name)
                return original_extractfile(self, member)
            with mock.patch.object(tarfile.TarFile, "extractfile", spy_extractfile):
                with self.assertRaises(BackupError) as ctx:
                    backup_module.read_bundle(path)
            self.assertIn("exceeds", str(ctx.exception))
            # The oversized member's content must never be read into memory,
            # even though a member inserted before it in the tar was.
            self.assertIn("config.json", called_for)
            self.assertNotIn("env-manifest.txt", called_for)

            ok, _, issues = verify_bundle(path)
            self.assertFalse(ok)
            self.assertTrue(any("exceeds" in i for i in issues))

    def test_newer_schema_rejected(self):
        metadata = self._bundle()
        with mock.patch.object(backup_module, "SCHEMA_VERSION", 0):
            ok, _, issues = verify_bundle(Path(metadata["path"]))
        self.assertFalse(ok)
        self.assertTrue(any("newer" in i for i in issues))


class RestoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.source = make_instance(base / "source")
        self.target = make_instance(base / "target")
        self.target_db = make_db(str(base / "target" / "pinoc.db"))
        self.bundle_path = base / "bundle.tar"
        self.addCleanup(self._tmp.cleanup)
        build_bundle(self.source, self.bundle_path, make_db(str(base / "source" / "pinoc.db")))

    def test_restore_replaces_files_and_audits(self):
        (self.target / "config.json").write_text("{}")
        result = restore_bundle(self.bundle_path, self.target,
                                self.target / "pinoc.db", confirm="RESTORE")
        self.assertEqual(json.loads((self.target / "config.json").read_text())["devices_file"],
                         "config/devices.json")
        self.assertEqual(json.loads((self.target / "config" / "devices.json").read_text()),
                         {"devices": [{"id": "pi"}]})
        probe = Database(str(self.target / "pinoc.db"))
        probe.initialize()
        self.assertEqual(probe.scalar("SELECT COUNT(*) FROM device_metrics"), 1)
        self.assertEqual(probe.scalar("SELECT COUNT(*) FROM audit_records WHERE action='backup.restore'"), 1)
        self.assertIn("restart", result["note"])

    def test_confirmation_required(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(BackupError) as ctx:
                restore_bundle(self.bundle_path, self.target, self.target / "pinoc.db")
        self.assertIn("--yes", str(ctx.exception))
        with self.assertRaises(BackupError):
            restore_bundle(self.bundle_path, self.target, self.target / "pinoc.db", confirm="nope")
        self.assertEqual((self.target / "config.json").read_text(),
                         json.dumps(CONFIG))

    def test_interactive_confirmation_prompt(self):
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("builtins.input", return_value="RESTORE") as mocked_input:
            result = restore_bundle(self.bundle_path, self.target, self.target / "pinoc.db")
        mocked_input.assert_called_once()
        self.assertIn("restart", result["note"])

    def test_interactive_confirmation_rejected(self):
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("builtins.input", return_value="nope"):
            with self.assertRaises(BackupError):
                restore_bundle(self.bundle_path, self.target, self.target / "pinoc.db")

    def test_missing_required_secret(self):
        (self.target / ".env").write_text("PINOC_WEB_PORT=9999\n")
        with self.assertRaises(BackupError) as ctx:
            restore_bundle(self.bundle_path, self.target, self.target / "pinoc.db",
                           confirm="RESTORE")
        self.assertIn("PINOC_SECRET_KEY", str(ctx.exception))
        self.assertEqual((self.target / "config.json").read_text(), json.dumps(CONFIG))
        result = restore_bundle(self.bundle_path, self.target, self.target / "pinoc.db",
                                confirm="RESTORE", allow_missing_secrets=True)
        self.assertEqual(result["missing_secrets"], ["PINOC_SECRET_KEY"])

    def test_signed_bundle_requires_key(self):
        source2 = make_instance(Path(self._tmp.name) / "source2")
        bundle2 = Path(self._tmp.name) / "signed.tar"
        build_bundle(source2, bundle2, make_db(str(Path(self._tmp.name) / "src2.db")),
                     signing_key="k1")
        with self.assertRaises(BackupError) as ctx:
            restore_bundle(bundle2, self.target, self.target / "pinoc.db", confirm="RESTORE")
        self.assertIn("signing key", str(ctx.exception))

    def test_required_env_keys_helper(self):
        config = {"authentication": {"enabled": True}, "remote_host": "10.0.0.2"}
        self.assertEqual(
            required_env_keys(config, ["PINOC_SECRET_KEY", "CM5_SSH_PASS", "PINOC_WEB_PORT"],
                              ["PINOC_WEB_PORT"]),
            ["PINOC_SECRET_KEY", "CM5_SSH_PASS"])
        self.assertEqual(
            required_env_keys(config, ["PINOC_SECRET_KEY"], ["PINOC_SECRET_KEY"]), [])


def fake_runner(calls, table=None, code=0):
    def runner(args, **kwargs):
        calls.append((args, kwargs))
        for match, stdout in (table or []):
            if all(piece in args for piece in match):
                return subprocess.CompletedProcess(args, 0, stdout, "")
        return subprocess.CompletedProcess(args, code, "", "")
    return runner


class BackupServiceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.instance = make_instance(base)
        make_db(str(base / "pinoc.db"))
        self.destination = base / "dest"
        self.addCleanup(self._tmp.cleanup)

    def service(self, **config):
        calls = []
        value = {"enabled": True, "interval_hours": 24, "keep": 2,
                 "destination": {"type": "path", "path": str(self.destination)}}
        value.update(config)
        service = BackupService(value, app_dir=self.instance,
                                database_path=str(self.instance / "pinoc.db"),
                                runner=fake_runner(calls))
        return service, calls

    def test_disabled_by_default(self):
        service = BackupService({}, app_dir=self.instance)
        self.assertFalse(service.enabled)
        self.assertFalse(service.thread.is_alive())

    def test_path_destination_runs_and_rotates(self):
        self.destination.mkdir(parents=True)
        for n in range(3):
            old = self.destination / f"pinoc-bundle-old{n}.tar"
            old.write_bytes(b"x")
            os.utime(old, (time.time() - 100 + n, time.time() - 100 + n))
        service, _ = self.service(keep=2)
        status = service.run_backup()
        self.assertIsNone(status["last_error"])
        self.assertIsNotNone(status["last_bundle"])
        self.assertIsNotNone(status["last_run"])
        bundles = list(self.destination.glob("pinoc-bundle-*.tar"))
        self.assertEqual(len(bundles), 2)
        self.assertTrue(any(p.stat().st_size > 1000 for p in bundles))

    def test_ssh_destination_fixed_argv(self):
        calls = []
        delivered = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == "scp":
                delivered.append(Path(args[-2]).name)
            if args[0] == "ssh" and "ls" in args:
                newest = delivered[-1] if delivered else "pinoc-bundle-new.tar"
                return subprocess.CompletedProcess(args, 0,
                                                   f"{newest}\npinoc-bundle-old.tar\n;rm -rf /\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        service = BackupService({
            "enabled": True, "keep": 1,
            "destination": {"type": "ssh", "host": "nas", "user": "pi",
                            "port": 2222, "path": "/var/backups/pinoc"},
        }, app_dir=self.instance, database_path=str(self.instance / "pinoc.db"),
            runner=runner)
        status = service.run_backup()
        self.assertIsNone(status["last_error"])
        scp = [args for args, _ in calls if args[0] == "scp"]
        self.assertTrue(scp)
        self.assertIn("-P", scp[0])
        self.assertIn("2222", scp[0])
        self.assertIn("BatchMode=yes", scp[0])
        self.assertIn("pi@nas:/var/backups/pinoc", " ".join(scp[0]))
        rms = [args for args, _ in calls if args[0] == "ssh" and "rm" in args]
        self.assertTrue(rms)
        self.assertIn("pinoc-bundle-old.tar", " ".join(rms[0]))
        # The injected non-bundle listing line must never be removed.
        for args in rms:
            self.assertNotIn(";rm -rf /", " ".join(args))
        for args, kwargs in calls:
            self.assertNotIn("shell", kwargs)
            self.assertNotIn("sh", args[:3])
        # _deliver() used to run its own "ls -1t" listing and discard the
        # result -- _rotate(), called right after, does the only listing
        # that's actually used for rotation.
        listings = [args for args, _ in calls if args[0] == "ssh" and "ls" in args]
        self.assertEqual(len(listings), 1)

    def test_failure_notifies(self):
        notifier = mock.MagicMock()
        notifier.enabled = True
        service = BackupService({"enabled": True,
                                 "destination": {"type": "path", "path": str(self.destination)}},
                                app_dir=self.instance / "missing",
                                database_path=str(self.instance / "pinoc.db"),
                                notifier=notifier)
        status = service.run_backup()
        self.assertIsNotNone(status["last_error"])
        notifier.enqueue.assert_called_once()
        transition, alert = notifier.enqueue.call_args.args[:2]
        self.assertEqual(transition, "open")
        self.assertEqual(alert["severity"], "critical")

    def test_invalid_destination_disables(self):
        service = BackupService({"enabled": True,
                                 "destination": {"type": "carrier-pigeon", "path": "/x"}})
        self.assertFalse(service.enabled)


class ConfigValidationTest(unittest.TestCase):
    def test_valid(self):
        for section in (
            {"enabled": True, "interval_hours": 24, "keep": 7,
             "destination": {"type": "path", "path": "/mnt/nas/pinoc"}},
            {"enabled": False},
            {"enabled": True, "interval_hours": 1, "keep": 1,
             "signing_key_env": "PINOC_BACKUP_KEY",
             "destination": {"type": "ssh", "host": "nas.local", "user": "pi",
                             "port": 22, "path": "/var/backups"}},
        ):
            validate_backups({"backups": section})

    def test_invalid(self):
        for section, needle in (
            ({"enabled": "yes"}, "boolean"),
            ({"enabled": True, "interval_hours": 0}, "interval_hours"),
            ({"enabled": True, "interval_hours": 9999}, "interval_hours"),
            ({"enabled": True, "keep": 100}, "keep"),
            ({"enabled": True}, "destination"),
            ({"enabled": True, "destination": {"type": "ftp"}}, "type"),
            ({"enabled": True, "destination": {"type": "path", "path": "relative"}}, "absolute"),
            ({"enabled": True, "destination": {"type": "ssh", "host": "a;b", "user": "pi", "path": "/x"}}, "host"),
            ({"enabled": True, "destination": {"type": "ssh", "host": "h", "user": "u u", "path": "/x"}}, "user"),
            ({"enabled": True, "destination": {"type": "ssh", "host": "h", "port": 0, "path": "/x"}}, "port"),
            ({"enabled": True, "signing_key_env": "bad name"}, "signing_key_env"),
        ):
            with self.assertRaises(ValueError) as ctx:
                validate_backups({"backups": section})
            self.assertIn(needle, str(ctx.exception))

    def test_full_validate_config_accepts_backups(self):
        validate_config({"polling": {"local_seconds": 10},
                         "backups": {"enabled": True,
                                     "destination": {"type": "path", "path": "/x"}}},
                        Path(tempfile.mkdtemp()))


def build_web(tmp: str, backups=None, auth=True):
    db = Database(f"{tmp}/db.sqlite")
    assert db.initialize()
    history = HistoryManager(db, {})
    state = PiNOCState()
    instance = Path(tmp) / "instance"
    make_instance(instance)
    config = {"TESTING": True, "AUTH_ENABLED": auth, "SECRET_KEY": "test-secret",
              "DATABASE": db, "APP_DIR": str(instance),
              "PINOC_CONFIG": {"authentication": {"enabled": auth}}}
    return create_app(state, config, history, None, None, backups), db


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _app(self, **kwargs):
        app, db = build_web(self._tmp.name, **kwargs)
        self.addCleanup(app.extensions["pinoc_actions"].stop)
        return app, db

    def _login(self, client, username, role="administrator"):
        security = self.app.extensions["pinoc_security"]
        security.create_user(username, "correct horse battery", role)
        client.get("/login")
        with client.session_transaction() as session:
            csrf = session["csrf_token"]
        client.post("/login", data={"username": username,
                                    "password": "correct horse battery",
                                    "csrf_token": csrf})

    def test_status_permissions(self):
        self.app, _ = self._app()
        client = self.app.test_client()
        self.assertEqual(client.get("/api/backup").status_code, 401)
        self._login(client, "boss", "administrator")
        self.assertEqual(client.get("/api/backup").status_code, 200)
        self.assertEqual(client.get("/api/backup").get_json()["enabled"], False)
        watcher = self.app.extensions["pinoc_security"].create_token("boss", ["read:fleet"])
        self.assertEqual(client.get("/api/backup",
                                     headers={"Authorization": f"Bearer {watcher}"}).status_code, 403)
        self._login(client, "plain", "viewer")
        self.assertEqual(client.get("/api/backup").status_code, 403)

    def test_export_download_and_audit(self):
        self.app, db = self._app()
        client = self.app.test_client()
        self._login(client, "boss")
        response = client.get("/api/backup/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/x-tar")
        self.assertTrue(response.headers["Content-Disposition"].startswith("attachment"))
        self.assertGreater(len(response.data), 1000)
        self.assertEqual(db.scalar(
            "SELECT COUNT(*) FROM audit_records WHERE action='backup.export'"), 1)
        self._login(client, "plain", "viewer")
        self.assertEqual(client.get("/api/backup/export").status_code, 403)

    def test_run_now(self):
        # POST /api/backup/run must not block the request on the actual
        # scp/local-copy delivery -- it queues the run on its own thread
        # and returns immediately; the audit record for the completed run
        # lands shortly after, once that background thread finishes.
        calls = []
        destination = Path(self._tmp.name) / "dest"
        backups = BackupService(
            {"enabled": True, "destination": {"type": "path", "path": str(destination)}},
            app_dir=Path(self._tmp.name) / "instance",
            database_path=f"{self._tmp.name}/db.sqlite", runner=fake_runner(calls))
        self.app, db = self._app(backups=backups)
        client = self.app.test_client()
        self._login(client, "boss")
        csrf = client.get("/api/session").get_json()["csrf_token"]
        response = client.post("/api/backup/run", headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.get_json()["queued"])
        end = time.time() + 5
        while time.time() < end and db.scalar(
                "SELECT COUNT(*) FROM audit_records WHERE action='backup.run'") != 1:
            time.sleep(.01)
        self.assertEqual(db.scalar(
            "SELECT COUNT(*) FROM audit_records WHERE action='backup.run'"), 1)
        self.assertIsNone(backups.status()["last_error"])
        self.assertEqual(client.post("/api/backup/run", headers={"X-CSRF-Token": csrf}).status_code, 202)

    def test_run_now_does_not_block_the_request_on_slow_delivery(self):
        def slow_runner(args, **kwargs):
            time.sleep(0.3)
            return subprocess.CompletedProcess(args, 0, "", "")
        backups = BackupService(
            {"enabled": True, "destination": {"type": "ssh", "host": "nas.local", "path": "/backups"}},
            app_dir=Path(self._tmp.name) / "instance",
            database_path=f"{self._tmp.name}/db.sqlite", runner=slow_runner)
        self.app, db = self._app(backups=backups)
        client = self.app.test_client()
        self._login(client, "boss")
        csrf = client.get("/api/session").get_json()["csrf_token"]
        started = time.monotonic()
        response = client.post("/api/backup/run", headers={"X-CSRF-Token": csrf})
        elapsed = time.monotonic() - started
        self.assertEqual(response.status_code, 202)
        # The request itself must return immediately -- not wait on the
        # (here, deliberately slow) scp delivery -- so it can never tie up
        # a Waitress worker thread for the transfer's duration.
        self.assertLess(elapsed, 0.3)
        end = time.time() + 3
        while time.time() < end and backups.status()["last_run"] is None:
            time.sleep(.01)
        self.assertIsNotNone(backups.status()["last_run"])

    def test_run_now_without_service(self):
        self.app, _ = self._app()
        client = self.app.test_client()
        self._login(client, "boss")
        csrf = client.get("/api/session").get_json()["csrf_token"]
        self.assertEqual(client.post("/api/backup/run",
                                     headers={"X-CSRF-Token": csrf}).status_code, 409)


if __name__ == "__main__":
    unittest.main()
