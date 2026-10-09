"""Tests for the Python virtual-environment inventory (PiNOC 2.0 Phase 1,
P1-R05): ``pinoc/venvs.py`` plus the fleet's ``__VENVSCAN__`` /
``__VENVPKGS__`` sections.

The contract under test:

* **Discovery** rides the fleet poll on its own low cadence: filesystem
  only (the pyvenv.cfg Python version and the site-packages dist-info
  listing -- nothing from a venv is ever executed), with every path the
  service already knows ``!``-marked so a *deleted* environment reports
  ``missing`` instead of vanishing.
* **States**: ``healthy`` / ``broken`` / ``inaccessible`` / ``missing``
  are established by the scan; a freshness overlay turns an aged row into
  ``stale`` while its last concrete state is preserved. A failed
  collection never erases the last facts -- it only lets them age.
* **Packages** are timestamped point-in-time snapshots. Definite pip
  verdicts carry forward by name across filesystem-only re-scans (the
  inventory never invents a verdict); a missing/inaccessible environment
  freezes its last snapshot.
* **Links** to the repositories / applications / projects models are
  learned by path containment and device project membership; they only
  gain, they never fight the scan.
* **Phase 1 is read-only**: the one web write is the ``venv.refresh``
  action, which re-requests the inventory on the device's next fleet poll.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.config_store import validate_config, validate_venvs
from pinoc.collectors.fleet import (
    _venv_entries,
    parse_dist_info,
    parse_venv_packages,
    parse_venvs,
)
from pinoc.database import SCHEMA_VERSION, Database
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.venvs import VENV_STATES, VenvError, VenvsService
from pinoc.web.app import create_app

UTC = timezone.utc
NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
# Tight staleness so the freshness floor is easy to trip with a fixed clock.
DEFAULT_VENVS_CONFIG = {"enabled": True, "refresh_seconds": 300, "stale_seconds": 300}


class _RecordingHistory:
    """Duck-typed stand-in for HistoryManager in service-level tests: the
    service keeps it to record discovery/state-change events, so a
    recorder is the cleanest way to assert exactly which events fired."""

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
        "INSERT OR IGNORE INTO devices(device_id,hostname,friendly_name,created_at,updated_at) "
        "VALUES(?,?,?,?,?)",
        (device_id, hostname or device_id, device_id.title(),
         NOW.isoformat(), NOW.isoformat()))


def _setup_service(self, with_state=False, config=None):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.db = Database(f"{self._tmp.name}/db.sqlite")
    assert self.db.initialize()
    self.audit = []
    self.history = _RecordingHistory()
    self.state = PiNOCState() if with_state else None
    self.service = VenvsService(
        self.db, state=self.state, history=self.history,
        config=config if config is not None else DEFAULT_VENVS_CONFIG,
        audit=_record_audit.__get__(self, type(self)))
    self._device_row = lambda device_id, hostname=None: _device_row(
        self, device_id, hostname=hostname)
    self._row = lambda device_id, path: _row(self, device_id, path)


def _venv_entry(path, python="3.12.4", count=None, flags="ok", packages=None):
    """One venv scan entry in the exact shape the fleet's ``parse_venvs``
    emits (the shape ``DeviceState.venvs`` carries)."""
    packages = packages or []
    if count is None:
        count = len(packages) or None
    return {"path": path, "python": python, "package_count": count,
            "flags": flags, "packages": packages}


def _device_state(self, device_id, venvs=None, venv_scan_at=None,
                  online=True, last_seen=None, replace=False):
    """Publish one device's live state carrying the venv-relevant fields.

    ``replace=True`` makes the publish wholesale (the fleet's contract):
    devices not in the publish are removed from the live state."""
    self.state.publish([
        DeviceState(id=device_id, hostname=device_id,
                    friendly_name=device_id.title(),
                    online=online, health="healthy",
                    venvs=venvs or [],
                    venv_scan_at=venv_scan_at,
                    last_seen=last_seen or NOW.isoformat(),
                    last_successful_collection=last_seen or NOW.isoformat())
    ], replace=replace)


def _row(self, device_id, path):
    rows = self.db.rows("SELECT * FROM venvs WHERE device_id=? AND path=?",
                        (device_id, path))
    return self.service._decode_venv(rows[0]) if rows else None


# -- schema -----------------------------------------------------------------

class TestDatabaseSchema(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def test_schema_version_matches_constant(self):
        # The venv inventory introduced schema v24; assert the DB migrated to
        # the current constant (later Phase 1 migrations advance it further).
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        self.assertEqual(self.db.scalar("SELECT version FROM schema_version"),
                         SCHEMA_VERSION)

    def test_migration_creates_the_tables(self):
        tables = {row["name"] for row in self.db.rows(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("venvs", tables)
        self.assertIn("venv_packages", tables)

    def test_migration_creates_the_indexes(self):
        indexes = {row["name"] for row in self.db.rows(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        for name in ("venvs_device", "venvs_state", "venvs_repo",
                     "venvs_project", "venv_packages_venv",
                     "venv_packages_scanned"):
            self.assertIn(name, indexes)

    def test_unique_venv_per_device_and_path(self):
        self.db.execute(
            "INSERT INTO venvs(device_id,path,source,created_at,updated_at) "
            "VALUES(?,?,?,?,?)", ("pi", "/opt/a", "fleet_venvscan",
                                  NOW.isoformat(), NOW.isoformat()))
        with self.assertRaises(Exception):
            self.db.execute(
                "INSERT INTO venvs(device_id,path,source,created_at,updated_at) "
                "VALUES(?,?,?,?,?)", ("pi", "/opt/a", "fleet_venvscan",
                                      NOW.isoformat(), NOW.isoformat()))
        # The same path on a *different* device is a different environment.
        self.db.execute(
            "INSERT INTO venvs(device_id,path,source,created_at,updated_at) "
            "VALUES(?,?,?,?,?)", ("spare", "/opt/a", "fleet_venvscan",
                                  NOW.isoformat(), NOW.isoformat()))


# -- fleet parsers -----------------------------------------------------------

class TestFleetParsers(unittest.TestCase):
    def test_parse_dist_info_splits_name_and_version(self):
        self.assertEqual(parse_dist_info("requests-2.31.0.dist-info"),
                         ("requests", "2.31.0"))
        self.assertEqual(parse_dist_info("zope.interface-5.4.0.dist-info"),
                         ("zope.interface", "5.4.0"))
        self.assertEqual(parse_dist_info("no-version.dist-info"),
                         ("no-version", None))
        self.assertEqual(parse_dist_info("plain"), ("plain", None))

    def test_parse_venvs_dedups_and_binds(self):
        text = "\n".join([
            "V|/opt/a|3.11|5|ok",
            "P|/opt/a|requests-2.31.0.dist-info",
            "P|/opt/a|flask-2.0.1.dist-info",
            "P|/opt/a|requests-2.31.0.dist-info",  # duplicate package: dropped
            "V|/opt/a|3.11|5|ok",  # duplicate venv: dropped (first wins)
            "V|/opt/gone|unknown|0|missing",
            "V|/opt/broken|3.12|0|broken",
            "P|/opt/broken|numpy-1.24.0.dist-info",
            "garbage line without pipes",
            "V|too-short",  # malformed: skipped
        ])
        entries = parse_venvs(text)
        self.assertEqual([e["path"] for e in entries],
                         ["/opt/a", "/opt/gone", "/opt/broken"])
        ok = entries[0]
        self.assertEqual(ok["python"], "3.11")
        self.assertEqual(ok["package_count"], 5)
        self.assertEqual(ok["flags"], "ok")
        self.assertEqual([p["name"] for p in ok["packages"]],
                         ["requests", "flask"])
        self.assertEqual(entries[1]["flags"], "missing")
        self.assertEqual(entries[1]["packages"], [])
        self.assertEqual(entries[2]["packages"][0],
                         {"name": "numpy", "version": "1.24.0"})

    def test_parse_venvs_output_is_bounded(self):
        lines = [f"V|/v{i}|3.11|0|ok" for i in range(120)]
        self.assertEqual(len(parse_venvs("\n".join(lines), max_venvs=100)), 100)
        lines = ["V|/v|3.11|0|ok"] + [
            f"P|/v|pkg{i}-1.0.dist-info" for i in range(2500)]
        entry = parse_venvs("\n".join(lines), max_packages=2000)[0]
        self.assertEqual(len(entry["packages"]), 2000)

    def test_parse_venv_packages_carries_the_verdict_metadata(self):
        text = "\n".join([
            "O|/opt/a|",
            "[",
            "  {",
            '    "name": "requests",',
            '    "version": "2.31.0",',
            '    "latest_version": "2.32.0"',
            "  }",
            "]",
            "Q|/opt/a|0|1",
        ])
        result = parse_venv_packages(text)
        self.assertTrue(result["/opt/a"]["ok"])
        self.assertTrue(result["/opt/a"]["complete"])
        self.assertEqual(result["/opt/a"]["packages"], [
            {"name": "requests", "version": "2.31.0",
             "latest_version": "2.32.0", "outdated": True}])

    def test_failed_pip_is_not_a_verdict(self):
        # pip exited non-zero (no network / no pip): the marker exists, the
        # output does not -- the verdict must read as "nothing this round".
        result = parse_venv_packages("O|/opt/x|\nQ|/opt/x|1|0")
        self.assertFalse(result["/opt/x"]["ok"])
        self.assertFalse(result["/opt/x"]["complete"])
        self.assertEqual(result["/opt/x"]["packages"], [])

    def test_ok_but_empty_listing_is_a_complete_verdict(self):
        result = parse_venv_packages("O|/opt/y|\n[\n]\nQ|/opt/y|0|1")
        self.assertTrue(result["/opt/y"]["ok"])
        self.assertTrue(result["/opt/y"]["complete"])
        self.assertEqual(result["/opt/y"]["packages"], [])

    def test_marker_without_q_line_is_not_a_verdict(self):
        # An older agent that never learned the Q line: the marker is
        # recorded, but the verdict must be "not definitive".
        result = parse_venv_packages("O|/opt/z|\n")
        self.assertFalse(result["/opt/z"]["ok"])
        self.assertFalse(result["/opt/z"]["complete"])

    def test_truncated_output_is_lenient_but_not_definitive(self):
        text = ("O|/opt/t|\n[\n  {\n    \"name\": \"aaa\",\n    "
                "\"version\": \"1.0\",\n    \"latest_version\": \"1.1\"\n  },\n"
                "  {\n    \"name\": \"bbb\",\n    \"version\": \"2")
        result = parse_venv_packages(text)
        # The complete object parses; the truncated one is dropped (its
        # version value never closed, so it cannot be paired).
        self.assertEqual(result["/opt/t"]["packages"], [
            {"name": "aaa", "version": "1.0",
             "latest_version": "1.1", "outdated": True}])
        self.assertFalse(result["/opt/t"]["complete"])

    def test_merge_complete_verdict_marks_everything(self):
        data = {
            "VENVSCAN": "V|/opt/a|3.11|2|ok\n"
                        "P|/opt/a|requests-2.31.0.dist-info\n"
                        "P|/opt/a|flask-2.0.1.dist-info",
            "VENVPKGS": "O|/opt/a|\n"
                        "Q|/opt/a|0|1",  # ok + untruncated, nothing outdated
        }
        (entry,) = _venv_entries(data)
        flags = {p["name"]: p.get("outdated") for p in entry["packages"]}
        self.assertEqual(flags, {"requests": False, "flask": False})

    def test_merge_failed_check_flags_only_what_pip_listed(self):
        data = {
            "VENVSCAN": "V|/opt/a|3.11|2|ok\n"
                        "P|/opt/a|requests-2.31.0.dist-info\n"
                        "P|/opt/a|flask-2.0.1.dist-info",
            "VENVPKGS": "O|/opt/a|\nQ|/opt/a|2|0",  # pip failed
        }
        (entry,) = _venv_entries(data)
        self.assertNotIn("outdated", entry["packages"][0])

    def test_merge_no_check_keeps_no_verdict(self):
        data = {
            "VENVSCAN": "V|/opt/a|3.11|1|ok\nP|/opt/a|requests-2.31.0.dist-info",
            "VENVPKGS": "",
        }
        (entry,) = _venv_entries(data)
        self.assertNotIn("outdated", entry["packages"][0])


# -- sources and the five states ----------------------------------------------

class TestServiceStates(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")

    def test_flag_to_state_mapping(self):
        _device_state(self, "pi", venvs=[
            _venv_entry("/opt/ok"),
            _venv_entry("/opt/broken", flags="broken"),
            _venv_entry("/opt/hidden", flags="inaccessible"),
            _venv_entry("/opt/gone", python="unknown", flags="missing"),
            _venv_entry("/opt/weird", flags="???"),  # unrecognized: unknown
        ], venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(self._row("pi", "/opt/ok")["state"], "healthy")
        self.assertEqual(self._row("pi", "/opt/broken")["state"], "broken")
        self.assertEqual(self._row("pi", "/opt/hidden")["state"], "inaccessible")
        self.assertEqual(self._row("pi", "/opt/gone")["state"], "missing")
        self.assertEqual(self._row("pi", "/opt/weird")["state"], "unknown")

    def test_states_are_the_five_spec_states(self):
        self.assertEqual(tuple(VENV_STATES),
                         ("healthy", "broken", "inaccessible", "missing", "stale"))

    def test_stale_after_freshness_floor(self):
        _device_state(self, "pi", venvs=[_venv_entry("/opt/ok")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        self.assertEqual(self._row("pi", "/opt/ok")["state"], "healthy")
        # The same scan re-observed later ages past the 300s floor; the last
        # concrete state is preserved in the reasons.
        self.service.tick(now=NOW + timedelta(seconds=400))
        venv = self._row("pi", "/opt/ok")
        self.assertEqual(venv["state"], "stale")
        self.assertTrue(any("last healthy" in reason for reason in venv["state_reasons"]))
        transitions = [e for e in self.history.events
                       if e["type"] == "venv_state_changed"]
        self.assertEqual(len(transitions), 1)
        self.assertEqual(transitions[0]["metadata"]["new_state"], "stale")

    def test_failed_collection_never_erases_last_facts(self):
        _device_state(self, "pi", venvs=[_venv_entry("/opt/ok", python="3.12.4")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        # A failed poll re-publishes the device with the same last scan (the
        # fleet's carry-forward): facts stay, only the age grows.
        _device_state(self, "pi", venvs=[_venv_entry("/opt/ok", python="3.12.4")],
                      venv_scan_at=NOW.isoformat(),
                      last_seen=(NOW + timedelta(hours=3)).isoformat(),
                      online=False)
        self.service.tick(now=NOW + timedelta(hours=3))
        venv = self._row("pi", "/opt/ok")
        self.assertEqual(venv["python_version"], "3.12.4")
        self.assertEqual(venv["state"], "stale")
        self.assertEqual(venv["scanned_at"], NOW.isoformat())

    def test_older_scan_does_not_rewind_facts(self):
        _device_state(self, "pi", venvs=[_venv_entry("/opt/ok", python="3.12.4")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        # A *late* delivery of an older scan must not rewrite the newer row.
        _device_state(self, "pi", venvs=[_venv_entry("/opt/ok", python="3.11.0")],
                      venv_scan_at=(NOW - timedelta(hours=1)).isoformat(),
                      last_seen=NOW.isoformat())
        self.service.tick(now=NOW)
        venv = self._row("pi", "/opt/ok")
        self.assertEqual(venv["python_version"], "3.12.4")
        self.assertEqual(venv["scanned_at"], NOW.isoformat())

    def test_unreported_device_ages_its_venvs(self):
        _device_state(self, "pi", venvs=[_venv_entry("/opt/ok")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        # The device leaves the live state entirely (a wholesale fleet
        # publish no longer includes it): its environments still age to
        # stale instead of vanishing -- the re-derivation runs over the
        # whole table, not just the live roster.
        _device_state(self, "spare", venvs=[], replace=True)
        self.service.tick(now=NOW + timedelta(hours=48))
        self.assertEqual(self._row("pi", "/opt/ok")["state"], "stale")


# -- package snapshots ---------------------------------------------------------

class TestPackages(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")

    def _venv_id(self, path="/opt/ok"):
        return self.db.scalar("SELECT venv_id FROM venvs WHERE path=?", (path,))

    def test_snapshot_replaces_and_latest_is_read(self):
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.31.0"},
                                  {"name": "flask", "version": "2.0.1"}])],
            venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.32.0"}])],
            venv_scan_at=(NOW + timedelta(hours=6)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=6))
        snapshot = self.service.packages(self._venv_id())
        self.assertEqual(snapshot["snapshot_at"], (NOW + timedelta(hours=6)).isoformat())
        self.assertEqual(snapshot["package_count"], 1)
        self.assertEqual([p["name"] for p in snapshot["packages"]], ["requests"])
        # The whole old snapshot is gone (the listing no longer contains flask).
        self.assertNotIn("flask", {p["name"] for p in snapshot["packages"]})

    def test_verdicts_carry_forward_by_name(self):
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.31.0",
                                   "outdated": True, "latest_version": "2.32.0"},
                                  {"name": "flask", "version": "2.0.1",
                                   "outdated": False}])],
            venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        # A periodic (filesystem-only) re-scan: no pip verdict this round --
        # the previous verdicts carry forward by name, the listing updates.
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.31.0"},
                                  {"name": "flask", "version": "2.1.0"},
                                  {"name": "newpkg", "version": "1.0"}])],
            venv_scan_at=(NOW + timedelta(hours=6)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=6))
        snapshot = self.service.packages(self._venv_id())
        flags = {p["name"]: p["outdated"] for p in snapshot["packages"]}
        self.assertEqual(flags, {"requests": True, "flask": False,
                                 "newpkg": None})
        row = self.db.rows("SELECT outdated_count FROM venvs WHERE path='/opt/ok'")[0]
        self.assertEqual(row["outdated_count"], 1)

    def test_never_checked_packages_stay_verdictless(self):
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.31.0"}])],
            venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        snapshot = self.service.packages(self._venv_id())
        self.assertIsNone(snapshot["outdated_count"])
        self.assertIsNone(snapshot["packages"][0]["outdated"])
        row = self.db.rows("SELECT outdated_count FROM venvs WHERE path='/opt/ok'")[0]
        self.assertIsNone(row["outdated_count"])

    def test_missing_environment_freezes_its_snapshot(self):
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.31.0",
                                   "outdated": True, "latest_version": "2.32.0"}])],
            venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", python="unknown", count=0, flags="missing",
            packages=[])], venv_scan_at=(NOW + timedelta(hours=6)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=6))
        venv = self._row("pi", "/opt/ok")
        self.assertEqual(venv["state"], "missing")
        # The last known listing stays visible (the environment is gone; what
        # it last showed is the useful record, aging out on the retention).
        snapshot = self.service.packages(self._venv_id())
        self.assertEqual(snapshot["package_count"], 1)
        self.assertEqual(snapshot["snapshot_at"], NOW.isoformat())
        self.assertEqual(snapshot["outdated_count"], 1)

    def test_inaccessible_environment_freezes_its_snapshot(self):
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", packages=[{"name": "requests", "version": "2.31.0"}])],
            venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        _device_state(self, "pi", venvs=[_venv_entry(
            "/opt/ok", flags="inaccessible", packages=[])],
            venv_scan_at=(NOW + timedelta(hours=6)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=6))
        snapshot = self.service.packages(self._venv_id())
        self.assertEqual(snapshot["package_count"], 1)  # frozen, not wiped


# -- links ---------------------------------------------------------------------

class TestLinks(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self.db.execute(
            "INSERT INTO projects(project_id,slug,name,created_at,updated_at)"
            " VALUES(1,'demo','Demo',?,?)", (NOW.isoformat(), NOW.isoformat()))
        self.db.execute(
            "INSERT INTO repositories(slug,name,canonical_url,project_slug,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("web", "Web", "https://example.com/web", "demo",
             NOW.isoformat(), NOW.isoformat()))
        self.db.execute(
            "INSERT INTO applications(slug,name,project_slug,created_at,updated_at)"
            " VALUES(?,?,?,?,?)", ("display", "Display", "demo",
                                    NOW.isoformat(), NOW.isoformat()))
        self.db.execute(
            "INSERT INTO deployments(repo_slug,device_id,local_path,"
            "application_slug,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("web", "pi", "/opt/repo", "display",
             NOW.isoformat(), NOW.isoformat()))

    def test_path_containment_links_repo_app_and_project(self):
        _device_state(self, "pi", venvs=[_venv_entry("/opt/repo/.venv")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        venv = self._row("pi", "/opt/repo/.venv")
        self.assertEqual(venv["repo"], "web")
        self.assertEqual(venv["app"], "display")
        self.assertEqual(venv["project"], "demo")

    def test_device_outside_any_checkout_has_no_links(self):
        _device_state(self, "pi", venvs=[_venv_entry("/elsewhere/.venv")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        venv = self._row("pi", "/elsewhere/.venv")
        self.assertIsNone(venv["repo"])
        self.assertIsNone(venv["app"])
        self.assertIsNone(venv["project"])

    def test_project_falls_back_to_device_membership(self):
        self.db.execute(
            "INSERT INTO project_members(project_id,kind,object_id,added_at)"
            " VALUES(1,'device',?,?)", ("pi", NOW.isoformat()))
        _device_state(self, "pi", venvs=[_venv_entry("/elsewhere/.venv")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        venv = self._row("pi", "/elsewhere/.venv")
        self.assertIsNone(venv["repo"])
        self.assertEqual(venv["project"], "demo")

    def test_links_only_gain_they_never_clear(self):
        _device_state(self, "pi", venvs=[_venv_entry("/opt/repo/.venv")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)
        # The deployment disappears from the model; the venv keeps the links
        # it learned (the scan carries no repo/app knowledge of its own).
        self.db.execute(
            "UPDATE deployments SET local_path='' WHERE device_id='pi'")
        _device_state(self, "pi", venvs=[_venv_entry("/opt/repo/.venv")],
                      venv_scan_at=(NOW + timedelta(hours=6)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=6))
        venv = self._row("pi", "/opt/repo/.venv")
        self.assertEqual(venv["repo"], "web")
        self.assertEqual(venv["app"], "display")


# -- read API ------------------------------------------------------------------

class TestReadApi(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")
        self.db.execute(
            "INSERT INTO projects(project_id,slug,name,created_at,updated_at)"
            " VALUES(0,'proj','Proj',?,?)", (NOW.isoformat(), NOW.isoformat()))
        self.db.execute(
            "INSERT INTO repositories(slug,name,canonical_url,project_slug,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("web", "Web", "https://example.com/web", "proj",
             NOW.isoformat(), NOW.isoformat()))
        self.db.execute(
            "INSERT INTO deployments(repo_slug,device_id,local_path,"
            "created_at,updated_at) VALUES(?,?,?,?,?)",
            ("web", "pi", "/opt/web", NOW.isoformat(), NOW.isoformat()))
        _device_state(self, "pi", venvs=[
            _venv_entry("/opt/ok"),
            _venv_entry("/opt/broken", flags="broken"),
            _venv_entry("/opt/gone", python="unknown", flags="missing"),
            _venv_entry("/opt/web/.venv"),
        ], venv_scan_at=NOW.isoformat())
        _device_state(self, "spare", venvs=[_venv_entry("/opt/clean")],
                      venv_scan_at=NOW.isoformat())
        self.service.tick(now=NOW)

    def test_list_and_filters(self):
        self.assertEqual(len(self.service.list()), 5)
        self.assertEqual(len(self.service.list(device="pi")), 4)
        self.assertEqual(len(self.service.list(state="missing")), 1)
        self.assertEqual(len(self.service.list(state="stale")), 0)
        self.assertEqual(len(self.service.list(state="unknown")), 0)
        self.assertEqual([v["path"] for v in self.service.list(device="pi", state="broken")],
                         ["/opt/broken"])
        self.assertEqual([v["path"] for v in self.service.list(project="proj")],
                         ["/opt/web/.venv"])
        self.assertEqual(self.service.list(project="ghost"), [])
        self.assertEqual([(v["path"], v["repo"]) for v in self.service.list(repo="web")],
                         [("/opt/web/.venv", "web")])
        with self.assertRaises(VenvError):
            self.service.list(state="bogus")

    def test_list_is_worst_state_first_within_device(self):
        rows = self.service.list(device="pi")
        self.assertEqual([v["path"] for v in rows],
                         ["/opt/gone", "/opt/broken", "/opt/ok", "/opt/web/.venv"])
        self.assertEqual([v["state"] for v in rows],
                         ["missing", "broken", "healthy", "healthy"])
        self.assertEqual([v["repo"] for v in rows if v["path"] == "/opt/web/.venv"],
                         ["web"])

    def test_attention_is_worst_first_fleet_wide(self):
        rows = self.service.attention()
        self.assertEqual([v["path"] for v in rows], ["/opt/gone", "/opt/broken"])
        self.assertEqual(len(self.service.attention(limit=1)), 1)
        self.assertEqual(self.service.attention()[0]["path"], "/opt/gone")

    def test_device_venvs_posture(self):
        posture = self.service.device_venvs("pi")
        self.assertEqual(posture["venv_count"], 4)
        self.assertEqual(posture["state"], "missing")  # worst of its venvs
        self.assertEqual(posture["state_counts"]["missing"], 1)
        self.assertEqual(posture["state_counts"]["healthy"], 2)
        self.assertIsNone(self.service.device_venvs("nope"))
        # A known device with no environments reports an honest empty posture.
        self._device_row("bare")
        posture = self.service.device_venvs("bare")
        self.assertIsNotNone(posture)
        self.assertEqual(posture["venv_count"], 0)
        self.assertEqual(posture["state"], "unknown")

    def test_venv_lookup(self):
        venv_id = self.db.scalar(
            "SELECT venv_id FROM venvs WHERE path='/opt/broken'")
        venv = self.service.venv(venv_id)
        self.assertEqual(venv["path"], "/opt/broken")
        self.assertIsNone(self.service.venv(99999))
        self.assertIsNone(self.service.venv("not-an-int"))

    def test_packages_unknown_venv_is_none(self):
        self.assertIsNone(self.service.packages(99999))


# -- web surface -----------------------------------------------------------------

class TestWeb(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True,
                         "SECRET_KEY": "test-secret", "DATABASE": self.db},
            self.history, None)
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("alice", "pw1234567890", "viewer")
        self.security.create_user("bob", "pw1234567890", "administrator")
        self.client = self.app.test_client()
        self.db.execute(
            "INSERT INTO devices(device_id,hostname,friendly_name,created_at,updated_at)"
            " VALUES('pi','pi','Pi',?,?)", (NOW.isoformat(), NOW.isoformat()))
        self.service = self.app.extensions["pinoc_venvs"]

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

    def _post(self, path):
        # Session-authenticated writes must carry the CSRF token issued at
        # login; the security layer rejects session POSTs without one.
        with self.client.session_transaction() as session:
            csrf = session["csrf_token"]
        return self.client.post(path, data={"csrf_token": csrf})

    def _seed(self):
        self.state.publish([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                        health="healthy",
                        venvs=[_venv_entry("/opt/ok", packages=[
                            {"name": "requests", "version": "2.31.0",
                             "outdated": True, "latest_version": "2.32.0"},
                            {"name": "flask", "version": "2.0.1",
                             "outdated": False}]),
                            _venv_entry("/opt/gone", python="unknown",
                                        flags="missing", packages=[])],
                        venv_scan_at=NOW.isoformat(),
                        last_seen=NOW.isoformat(),
                        last_successful_collection=NOW.isoformat()),
        ], replace=True)
        self.service.tick(now=NOW)

    def test_app_builds_and_exposes_service(self):
        self.assertIsNotNone(self.service)
        self._login("bob")
        self.assertEqual(self.client.get("/venvs").status_code, 200)

    def test_unauthenticated_api_is_401(self):
        for path in ("/api/v1/venvs", "/api/v1/venvs/attention",
                     "/api/v1/devices/pi/venvs", "/api/v1/venvs/1/packages"):
            self.assertEqual(self.client.get(path).status_code, 401, msg=path)
        self.assertEqual(self.client.post("/api/v1/venvs/1/refresh").status_code, 401)

    def test_viewer_reads(self):
        self._seed()
        self._login("alice")
        for path in ("/api/v1/venvs", "/api/v1/venvs/attention",
                     "/api/v1/devices/pi/venvs", "/api/v1/venvs/1/packages"):
            self.assertEqual(self.client.get(path).status_code, 200, msg=path)
        body = self.client.get("/api/v1/venvs?state=missing").get_json()
        self.assertEqual(len(body["venvs"]), 1)
        self.assertEqual(body["venvs"][0]["path"], "/opt/gone")

    def test_token_scope_permissions_registered(self):
        permissions = self.app.config["TOKEN_SCOPE_PERMISSIONS"]
        for endpoint, permission in (
                ("api_v1_venvs", "view"),
                ("api_v1_venv_attention", "view"),
                ("api_v1_device_venvs", "view"),
                ("api_v1_venv_packages", "view"),
                ("api_v1_venv_refresh", "actions.execute")):
            self.assertEqual(permissions[endpoint], permission, msg=endpoint)

    def test_list_endpoint_and_filters(self):
        self._seed()
        self._login("bob")
        body = self.client.get("/api/v1/venvs").get_json()
        self.assertEqual(len(body["venvs"]), 2)
        self.assertEqual(self.client.get(
            "/api/v1/venvs?state=healthy").get_json()["venvs"][0]["path"], "/opt/ok")
        self.assertEqual(self.client.get(
            "/api/v1/venvs?state=bogus").status_code, 400)
        body = self.client.get("/api/v1/venvs?device=pi").get_json()
        self.assertEqual(len(body["venvs"]), 2)
        self.assertEqual(self.client.get(
            "/api/v1/venvs?device=ghost").get_json()["venvs"], [])

    def test_attention_endpoint(self):
        self._seed()
        self._login("bob")
        body = self.client.get("/api/v1/venvs/attention").get_json()
        self.assertEqual([v["path"] for v in body["venvs"]], ["/opt/gone"])
        self.assertEqual(self.client.get(
            "/api/v1/venvs/attention?limit=1").get_json()["venvs"][0]["state"], "missing")

    def test_device_venvs_endpoint(self):
        self._seed()
        self._login("bob")
        body = self.client.get("/api/v1/devices/pi/venvs").get_json()
        self.assertEqual(body["venv_count"], 2)
        self.assertEqual(body["state"], "missing")
        self.assertEqual(self.client.get(
            "/api/v1/devices/nope/venvs").status_code, 404)

    def test_packages_endpoint(self):
        self._seed()
        self._login("bob")
        venv_id = self.db.scalar(
            "SELECT venv_id FROM venvs WHERE path='/opt/ok'")
        body = self.client.get(f"/api/v1/venvs/{venv_id}/packages").get_json()
        self.assertEqual(body["package_count"], 2)
        self.assertEqual(body["outdated_count"], 1)
        self.assertEqual(body["snapshot_at"], NOW.isoformat())
        flags = {p["name"]: p["outdated"] for p in body["packages"]}
        self.assertEqual(flags, {"requests": True, "flask": False})
        self.assertEqual(self.client.get("/api/v1/venvs/9999/packages").status_code, 404)

    def test_viewer_cannot_refresh(self):
        self._seed()
        self._login("alice")
        venv_id = self.db.scalar("SELECT venv_id FROM venvs WHERE path='/opt/gone'")
        response = self._post(f"/api/v1/venvs/{venv_id}/refresh")
        self.assertEqual(response.status_code, 403)

    def test_admin_refresh_enqueues_the_action(self):
        self._seed()
        self._login("bob")
        venv_id = self.db.scalar("SELECT venv_id FROM venvs WHERE path='/opt/gone'")
        response = self._post(f"/api/v1/venvs/{venv_id}/refresh")
        self.assertEqual(response.status_code, 202)
        job = response.get_json()
        self.assertEqual(job["action"], "venv.refresh")
        self.assertEqual(job["target"], "/opt/gone")
        self.assertEqual(job["device_id"], "pi")

    def test_refresh_unknown_venv_is_404(self):
        self._seed()
        self._login("bob")
        self.assertEqual(self._post("/api/v1/venvs/9999/refresh").status_code, 404)

    def test_no_history_service_is_503(self):
        # Without a history database the service is absent; the endpoints
        # report unavailability rather than failing the process. There is no
        # security layer either (no database for the users table), so an
        # unauthenticated request must reach the 503 branch directly.
        app = create_app(PiNOCState(),
                         {"TESTING": True, "AUTH_ENABLED": True,
                          "SECRET_KEY": "test-secret"}, None, None)
        self.assertIsNone(app.extensions["pinoc_venvs"])
        client = app.test_client()
        for path in ("/api/v1/venvs", "/api/v1/venvs/attention",
                     "/api/v1/devices/pi/venvs", "/api/v1/venvs/1/packages"):
            self.assertEqual(client.get(path).status_code, 503, msg=path)
        self.assertEqual(client.post("/api/v1/venvs/1/refresh").status_code, 503)
        actions = app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()


# -- configuration validation -----------------------------------------------------

class TestConfigValidation(unittest.TestCase):
    def test_valid_section_accepted(self):
        validate_venvs({"venvs": {
            "enabled": False, "refresh_seconds": 60, "stale_seconds": 300,
            "venvs_check_seconds": 21600, "package_retention_days": 30,
            "roots": ["/opt/venvs"], "max_venvs": 100, "max_packages": 2000}})

    def test_absent_section_is_valid(self):
        validate_venvs({})
        validate_venvs({"venvs": None})

    def test_invalid_values_rejected(self):
        cases = [
            {"venvs": "on"},
            {"venvs": {"enabled": "yes"}},
            {"venvs": {"refresh_seconds": 29}},
            {"venvs": {"refresh_seconds": 86401}},
            {"venvs": {"refresh_seconds": True}},
            {"venvs": {"stale_seconds": 59}},
            {"venvs": {"stale_seconds": 2592001}},
            {"venvs": {"venvs_check_seconds": 59}},
            {"venvs": {"venvs_check_seconds": 86401}},
            {"venvs": {"venvs_check_seconds": "soon"}},
            {"venvs": {"package_retention_days": 0}},
            {"venvs": {"package_retention_days": 3651}},
            {"venvs": {"package_retention_days": "30"}},
            {"venvs": {"max_venvs": 0}},
            {"venvs": {"max_venvs": 501}},
            {"venvs": {"max_packages": 10001}},
            {"venvs": {"roots": "/opt/venvs"}},
            {"venvs": {"roots": ["/opt/venvs", 42]}},
            {"venvs": {"roots": [""]}},
            {"venvs": {"roots": ["x" * 401]}},
            {"venvs": {"roots": ["/ok"] * 51}},
        ]
        for value in cases:
            with self.assertRaises(ValueError, msg=value):
                validate_venvs(value)

    def test_validate_config_runs_venvs(self):
        base = {"devices": [], "polling": {"fleet_seconds": 10}}
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            self.assertEqual(validate_config(
                {**base, "venvs": {"stale_seconds": 300}}, Path(tmp)),
                {**base, "venvs": {"stale_seconds": 300}})
            with self.assertRaises(ValueError):
                validate_config(
                    {**base, "venvs": {"stale_seconds": 5}}, Path(tmp))


# -- no-database degradation -------------------------------------------------------

class TestNoDatabase(unittest.TestCase):
    def setUp(self):
        self.service = VenvsService(None, state=PiNOCState(),
                                    config=DEFAULT_VENVS_CONFIG)

    def test_list_is_empty(self):
        self.assertEqual(self.service.list(), [])

    def test_attention_is_empty(self):
        self.assertEqual(self.service.attention(), [])

    def test_device_venvs_is_none(self):
        self.assertIsNone(self.service.device_venvs("pi"))

    def test_venv_is_none(self):
        self.assertIsNone(self.service.venv(1))

    def test_packages_is_none(self):
        self.assertIsNone(self.service.packages(1))

    def test_device_venv_roots_is_empty(self):
        self.assertEqual(self.service.device_venv_roots(), {})

    def test_tick_reports_unavailable(self):
        self.assertEqual(self.service.tick(now=NOW)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
