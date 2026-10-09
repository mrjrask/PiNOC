"""Coverage for the fleet software and version inventory (PiNOC 2.0
Phase 1, P1-R04).

Ten layers:

* :class:`TestDatabaseSchema` -- migration 23 (software_components) and
  its indexes, plus the per-application uniqueness constraint.
* :class:`TestNormalizeVersion` -- the raw/normalized comparison contract:
  every spelling of one version normalizes the same, the raw value is
  never lost, "unknown" stays honest.
* :class:`TestParseRuntimes` -- the fleet's bounded __RUNTIMES__ reader
  (a missing tool reports "unknown", malformed lines are skipped, output
  is capped).
* :class:`TestServiceSources` -- one source-refresh tick driven directly
  against a real database and state cache: every source (device state
  OS/kernel/architecture, runtimes, packages, agents, applications), the
  five states (current/update_available/security_update/stale/unknown)
  under the freshness floor, version-change and state events, newest-wins
  merge, and the failed-collection-never-erases acceptance criterion.
* :class:`TestPostureRows` -- every monitored device gets a software
  posture record, and the posture rollup is worst-of.
* :class:`TestReadApi` -- the service-level reads: list filters (device,
  name, kind, application, project, state), device_software, the
  available-vs-security updates split, and filter-honoring export rows.
* :class:`TestWeb` -- the HTTP surface: auth gating, viewer role, the
  token-scope table, all four endpoints, CSV vs JSON export, the
  no-history 503 degradation, and credential redaction.
* :class:`TestConfigValidation` -- the ``software`` configuration bounds.
* :class:`TestNoDatabase` -- graceful degradation to empty reads.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.collectors.fleet import parse_runtimes
from pinoc.config_store import validate_config, validate_software
from pinoc.database import Database, SCHEMA_VERSION
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.software import (
    KINDS,
    SOFTWARE_STATES,
    SoftwareError,
    SoftwareService,
    normalize_version,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc
NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
# Service-level config used by the tests (tight staleness so the freshness
# floor is easy to trip in a fixed-clock test).
DEFAULT_SOFTWARE_CONFIG = {"enabled": True, "refresh_seconds": 300, "stale_seconds": 300}


class _RecordingHistory:
    """Duck-typed stand-in for HistoryManager in service-level tests: the
    service keeps it to record version-change/state events, so a recorder
    is the cleanest way to assert exactly which events fired."""

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
    self.service = SoftwareService(
        self.db, state=self.state, history=self.history,
        config=config if config is not None else DEFAULT_SOFTWARE_CONFIG,
        audit=_record_audit.__get__(self, type(self)))
    self._device_row = lambda device_id, hostname=None: _device_row(
        self, device_id, hostname=hostname)
    self._components = lambda *keys: _components(self, *keys)


def _device_state(self, device_id, os_name="Raspbian", os_version="12",
                  kernel="6.6.31-v8", architecture="aarch64", runtimes=None,
                  packages=None, last_seen=None, online=True):
    """Publish one device's live state carrying the software-relevant
    fields (OS/kernel/architecture, the due-gated runtimes list, and the
    packages integration entry)."""
    integrations = {}
    if packages is not None:
        integrations["packages"] = packages
    self.state.publish([
        DeviceState(id=device_id, hostname=device_id, friendly_name=device_id.title(),
                    online=online, health="healthy",
                    os=os_name, os_version=os_version,
                    kernel=kernel, architecture=architecture,
                    runtimes=runtimes or [],
                    last_seen=last_seen or NOW.isoformat(),
                    last_successful_collection=last_seen or NOW.isoformat(),
                    integrations=integrations)
    ])


def _packages_status(updates=0, security=0, last_success=None, available=True):
    """The ``packages`` IntegrationStatus shape the fleet publishes."""
    return {
        "name": "packages", "available": available,
        "health": "warning" if security else "healthy",
        "last_success": last_success or NOW.isoformat(),
        "last_attempt": last_success or NOW.isoformat(),
        "data_source": "apt-get", "error": None,
        "data": {"updates_available": updates, "security_updates": security,
                 "reboot_required": False, "last_metadata_refresh": None},
        "critical": False,
    }


def _agent_row(self, device_id, version="2.0.0", last_seen=None,
               enabled=1, revoked=0):
    self.db.execute(
        "INSERT INTO agents(agent_id,device_id,credential_hash,agent_version,"
        "protocol_version,status,enabled,credential_revoked,last_seen,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (f"agent-{device_id}", device_id, "x" * 32, version, 1, "active",
         enabled, revoked, last_seen or NOW.isoformat(), NOW.isoformat()))


def _application(self, slug, name=None, device_id=None, version="1.2.3"):
    """Insert an application (with a tracked version) plus an instance on a
    device -- the application-version source of the inventory."""
    self.db.execute(
        "INSERT INTO applications(slug,name,version,version_source,lifecycle,"
        "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        (slug, name or slug.title(), version, "manual", "active",
         NOW.isoformat(), NOW.isoformat()))
    if device_id:
        self.db.execute(
            "INSERT INTO application_instances(app_slug,device_id,mechanism,"
            "target,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (slug, device_id, "systemd", f"{slug}.service", 1,
             NOW.isoformat(), NOW.isoformat()))


def _components(self, *keys):
    """Fetch stored components for the tests' assertions."""
    rows = self.db.rows("SELECT * FROM software_components ORDER BY name,kind")
    by_key = {(r["device_id"], r.get("application_slug"), r["name"], r["kind"]): r
              for r in rows}
    return {key: self.service._decode_component(by_key[key]) for key in keys}


# -- schema ---------------------------------------------------------------

class TestDatabaseSchema(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()

    def test_schema_version_matches_constant(self):
        # Software inventory introduced schema v23; assert the DB migrated to
        # the current constant (later Phase 1 migrations advance it further).
        self.assertGreaterEqual(SCHEMA_VERSION, 23)
        self.assertEqual(self.db.scalar("SELECT version FROM schema_version"), SCHEMA_VERSION)

    def test_migration_creates_the_table(self):
        tables = {row["name"] for row in self.db.rows(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("software_components", tables)

    def test_migration_creates_the_indexes(self):
        indexes = {row["name"] for row in self.db.rows(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        for name in ("software_components_device", "software_components_name",
                     "software_components_state"):
            self.assertIn(name, indexes)

    def test_unique_component_key_per_application(self):
        self.db.execute(
            "INSERT INTO software_components(device_id,application_slug,name,kind,"
            "source,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            ("pi", "desk", "Desk", "application", "applications",
             NOW.isoformat(), NOW.isoformat()))
        # The same (device, application, name, kind) cannot appear twice --
        # the upsert key the service relies on.
        with self.assertRaises(Exception):
            self.db.execute(
                "INSERT INTO software_components(device_id,application_slug,name,kind,"
                "source,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("pi", "desk", "Desk", "application", "applications",
                 NOW.isoformat(), NOW.isoformat()))


# -- normalized versions ---------------------------------------------------

class TestNormalizeVersion(unittest.TestCase):
    def test_spelling_variants_compare_equal(self):
        for spelling in ("v1.2.3", "V1.2.3", "1.2.3", " 1.2.3 "):
            self.assertEqual(normalize_version(spelling), "1.2.3", msg=spelling)

    def test_case_is_folded(self):
        self.assertEqual(normalize_version("8.1.0-RC1"), "8.1.0-rc1")

    def test_unknown_sentinel_is_preserved(self):
        self.assertEqual(normalize_version("unknown"), "unknown")

    def test_empty_and_missing(self):
        self.assertEqual(normalize_version(""), "")
        self.assertEqual(normalize_version(None), "")
        self.assertEqual(normalize_version("   "), "")

    def test_non_string_input_is_stringified(self):
        self.assertEqual(normalize_version(123), "123")


# -- fleet runtimes parser -------------------------------------------------

class TestParseRuntimes(unittest.TestCase):
    def test_versioned_runtimes(self):
        result = parse_runtimes("python3|3.12.4\nnode|v18.19.0\nnpm|10.2.0\ngit|2.45.0\n")
        self.assertEqual([entry["name"] for entry in result],
                         ["python3", "node", "npm", "git"])
        self.assertEqual(result[0]["version"], "3.12.4")

    def test_missing_tool_reports_unknown_not_error(self):
        result = parse_runtimes("python3|3.12.4\nnode|unknown\n")
        self.assertEqual(result[1], {"name": "node", "version": "unknown"})

    def test_malformed_lines_are_skipped(self):
        result = parse_runtimes("garbage\n\n|no-name\nok|1.0\n|1.0\n")
        self.assertEqual(result, [{"name": "ok", "version": "1.0"}])

    def test_empty_input(self):
        self.assertEqual(parse_runtimes(""), [])

    def test_output_is_bounded(self):
        text = "\n".join(f"rt{i}|1.{i}" for i in range(60))
        self.assertEqual(len(parse_runtimes(text, max_entries=50)), 50)


# -- sources and the five states -------------------------------------------

class TestServiceSources(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")

    def test_os_component_combines_name_and_release(self):
        _device_state(self, "pi", os_name="Raspbian", os_version="12",
                      kernel="", architecture="")
        self.service.tick(now=NOW)
        (component,) = self.service.list(device="pi")
        self.assertEqual(component["name"], "operating system")
        self.assertEqual(component["kind"], "os")
        self.assertEqual(component["version"], "Raspbian 12")
        self.assertEqual(component["normalized_version"], "raspbian 12")
        self.assertEqual(component["state"], "current")
        self.assertEqual(component["source"], "device_state")

    def test_kernel_and_architecture(self):
        _device_state(self, "pi")
        self.service.tick(now=NOW)
        components = self._components(
            ("pi", None, "kernel", "kernel"),
            ("pi", None, "architecture", "architecture"))
        self.assertEqual(components[("pi", None, "kernel", "kernel")]["version"], "6.6.31-v8")
        self.assertEqual(components[("pi", None, "architecture", "architecture")]["version"], "aarch64")
        self.assertEqual(components[("pi", None, "kernel", "kernel")]["state"], "current")

    def test_runtimes_installed_and_missing(self):
        _device_state(self, "pi", runtimes=[
            {"name": "python3", "version": "3.12.4"},
            {"name": "node", "version": "unknown"},
        ])
        self.service.tick(now=NOW)
        components = self._components(
            ("pi", None, "python3", "runtime"),
            ("pi", None, "node", "runtime"))
        self.assertEqual(components[("pi", None, "python3", "runtime")]["state"], "current")
        self.assertEqual(components[("pi", None, "node", "runtime")]["state"], "unknown")
        self.assertIn("not installed",
                       components[("pi", None, "node", "runtime")]["state_reasons"][0])
        self.assertEqual(components[("pi", None, "python3", "runtime")]["source"],
                         "fleet_runtimes")

    def test_packages_security_update(self):
        _device_state(self, "pi", packages=_packages_status(updates=5, security=2))
        self.service.tick(now=NOW)
        (component,) = self.service.list(device="pi", kind="package")
        self.assertEqual(component["kind"], "package")
        self.assertEqual(component["state"], "security_update")
        self.assertEqual(component["security_updates"], 2)
        self.assertEqual(component["pending_updates"], 5)
        self.assertTrue(any("2 security update(s)" in reason for reason in component["state_reasons"]))

    def test_packages_updates_only(self):
        _device_state(self, "pi", packages=_packages_status(updates=5, security=0))
        self.service.tick(now=NOW)
        (component,) = self.service.list(device="pi", kind="package")
        self.assertEqual(component["state"], "update_available")

    def test_packages_clean_is_current(self):
        _device_state(self, "pi", packages=_packages_status(updates=0, security=0))
        self.service.tick(now=NOW)
        (component,) = self.service.list(device="pi", kind="package")
        self.assertEqual(component["state"], "current")

    def test_agent_version_from_agents_table(self):
        _device_state(self, "pi")
        _agent_row(self, "pi", version="2.1.0")
        self.service.tick(now=NOW)
        (component,) = self.service.list(name="pi_noc_agent")
        self.assertEqual(component["kind"], "agent")
        self.assertEqual(component["version"], "2.1.0")
        self.assertEqual(component["source"], "agents")
        self.assertEqual(component["state"], "current")

    def test_disabled_agent_is_not_reported(self):
        _device_state(self, "pi")
        _agent_row(self, "pi", enabled=0)
        self.service.tick(now=NOW)
        self.assertEqual(self.service.list(name="pi_noc_agent"), [])

    def test_application_version_with_instance(self):
        _device_state(self, "pi")
        _application(self, "desk", name="Desk Display", device_id="pi", version="3.4.1")
        self.service.tick(now=NOW)
        (component,) = self.service.list(application="desk")
        self.assertEqual(component["kind"], "application")
        self.assertEqual(component["application"], "desk")
        self.assertEqual(component["version"], "3.4.1")
        self.assertEqual(component["state"], "current")

    def test_two_devices_are_separate_components(self):
        _device_state(self, "pi")
        _device_state(self, "spare", os_name="Debian", os_version="12")
        self.service.tick(now=NOW)
        components = self.service.list(kind="os")
        self.assertEqual({c["device_id"] for c in components}, {"pi", "spare"})
        versions = {c["device_id"]: c["version"] for c in components}
        self.assertEqual(versions, {"pi": "Raspbian 12", "spare": "Debian 12"})

    def test_version_change_updates_and_emits_event(self):
        _device_state(self, "pi")
        _application(self, "desk", device_id="pi", version="1.0.0")
        self.service.tick(now=NOW)
        # The application service bumps the version ...
        self.db.execute("UPDATE applications SET version=? WHERE slug='desk'", ("2.0.0",))
        self.db.execute("UPDATE applications SET updated_at=? WHERE slug='desk'",
                        ((NOW + timedelta(hours=1)).isoformat(),))
        self.service.tick(now=NOW + timedelta(hours=1))
        (component,) = self.service.list(application="desk")
        self.assertEqual(component["version"], "2.0.0")
        types = {event["type"] for event in self.history.events}
        self.assertIn("software_version_changed", types)
        change = next(event for event in self.history.events
                      if event["type"] == "software_version_changed")
        self.assertEqual(change["metadata"]["old_version"], "1.0.0")
        self.assertEqual(change["metadata"]["new_version"], "2.0.0")

    def test_spelling_change_is_not_a_version_change(self):
        _device_state(self, "pi")
        _application(self, "desk", device_id="pi", version="v1.2.3")
        self.service.tick(now=NOW)
        self.db.execute("UPDATE applications SET version=? WHERE slug='desk'", ("1.2.3",))
        self.db.execute("UPDATE applications SET updated_at=? WHERE slug='desk'",
                        ((NOW + timedelta(hours=1)).isoformat(),))
        self.service.tick(now=NOW + timedelta(hours=1))
        self.assertFalse(any(event["type"] == "software_version_changed"
                             for event in self.history.events))

    def test_state_change_emits_event_on_transitions_only(self):
        _device_state(self, "pi", packages=_packages_status(updates=3, security=0))
        # First discovery: four components (os, kernel, arch, packages), each
        # deriving its real state at creation -- no transition events yet.
        self.service.tick(now=NOW)
        self.assertEqual(len(self.history.events), 4)
        self.assertFalse(any(event["type"] == "software_state_changed"
                             for event in self.history.events))
        self.service.tick(now=NOW)  # identical re-observation: no new events
        self.assertEqual(len(self.history.events), 4)
        # apt refresh clears the counts -> back to current: one transition.
        # (The package's own last_success must move forward with the device
        # or the row ages to *stale* instead of *current* under the 300s
        # test floor.)
        _device_state(self, "pi", packages=_packages_status(
            updates=0, security=0,
            last_success=(NOW + timedelta(hours=1)).isoformat()),
            last_seen=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        self.assertTrue(any(event["type"] == "software_state_changed"
                            and event["metadata"]["new_state"] == "current"
                            for event in self.history.events))

    def test_stale_after_freshness_floor(self):
        _device_state(self, "pi")
        self.service.tick(now=NOW)
        self.assertEqual(self.service.list(device="pi")[0]["state"], "current")
        # Age past the floor (300s in the test config) without a newer
        # observation ...
        self.service.tick(now=NOW + timedelta(hours=1))
        component = next(c for c in self.service.list(device="pi")
                         if c["name"] == "operating system")
        self.assertEqual(component["state"], "stale")
        # ... and the last concrete state is preserved in the reason.
        self.assertTrue(any("last current" in reason for reason in component["state_reasons"]))
        self.assertEqual(component["version"], "Raspbian 12")  # facts preserved

    def test_failed_collection_never_erases_last_success(self):
        _device_state(self, "pi")
        _device_state(self, "spare", packages=_packages_status(updates=4, security=1))
        self.service.tick(now=NOW)
        # The devices vanish from the live state (the fleet went offline) ...
        self.state.publish([], replace=True)
        self.service.tick(now=NOW + timedelta(hours=1))
        pi = next(c for c in self.service.list(device="pi")
                  if c["name"] == "operating system")
        spare = next(c for c in self.service.list(device="spare")
                     if c["name"] == "packages")
        self.assertEqual(pi["state"], "stale")
        self.assertEqual(pi["version"], "Raspbian 12")  # ... the last success survives
        self.assertEqual(spare["state"], "stale")
        self.assertEqual(spare["security_updates"], 1)  # ... counts survive

    def test_older_source_does_not_rewind_observations(self):
        _device_state(self, "pi", last_seen=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        before = self.service.list(device="pi")[0]["observed_at"]
        # Re-report the same device at the *older* timestamp ...
        _device_state(self, "pi", last_seen=NOW.isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        after = self.service.list(device="pi")[0]["observed_at"]
        self.assertEqual(after, before)

    def test_application_removed_ages_rather_than_deletes(self):
        _device_state(self, "pi")
        _application(self, "desk", device_id="pi", version="1.0.0")
        self.service.tick(now=NOW)
        self.db.execute("UPDATE application_instances SET enabled=0")
        self.service.tick(now=NOW + timedelta(hours=1))
        component = next(c for c in self.service.list(device="pi")
                         if c["application"] == "desk")
        # The source no longer reports it; the row ages to stale, it is not
        # deleted.
        self.assertEqual(component["state"], "stale")
        self.assertEqual(component["version"], "1.0.0")


# -- posture records ---------------------------------------------------------

class TestPostureRows(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")

    def test_every_monitored_device_gets_a_posture_record(self):
        # A device the live state carries but which no source has ever
        # reported a component for still gets a (honest, unknown) record.
        _device_state(self, "pi", os_name="", os_version="", kernel="", architecture="",
                      runtimes=[])
        self.service.tick(now=NOW)
        (component,) = self.service.list(device="pi")
        self.assertEqual(component["name"], "operating system")
        self.assertEqual(component["state"], "unknown")
        # Once the fleet reports the OS, the same row is filled in, not
        # duplicated.
        _device_state(self, "pi", os_name="Raspbian", os_version="12",
                      kernel="6.6.31-v8", architecture="aarch64")
        self.service.tick(now=NOW + timedelta(hours=1))
        # The placeholder was filled in, not duplicated: os + kernel +
        # architecture, still exactly one row per component.
        self.assertEqual(len(self.service.list(device="pi")), 3)
        self.assertEqual(len(self.service.list(device="pi", kind="os")), 1)
        self.assertEqual(self.service.list(device="pi", kind="os")[0]["version"],
                         "Raspbian 12")

    def test_posture_rollup_is_worst_of(self):
        _device_state(self, "pi")
        _device_state(self, "spare", packages=_packages_status(updates=2, security=1))
        self._device_row("spare")
        self.service.tick(now=NOW)
        posture = self.service.posture()
        self.assertEqual(posture["device_count"], 2)
        self.assertEqual(posture["state"], "security_update")
        by_id = {d["device_id"]: d for d in posture["devices"]}
        self.assertEqual(by_id["pi"]["state"], "current")
        self.assertEqual(by_id["spare"]["state"], "security_update")
        self.assertEqual(posture["devices"][1]["state_counts"]["security_update"], 1)

    def test_posture_empty(self):
        self.assertEqual(self.service.posture()["state"], "unknown")
        self.assertEqual(self.service.posture()["device_count"], 0)


# -- read API ----------------------------------------------------------------

class TestReadApi(unittest.TestCase):
    def setUp(self):
        _setup_service(self, with_state=True)
        self._device_row("pi")
        self._device_row("spare")
        self._project("proj")
        # pi: a full posture with one security update (os, kernel, arch,
        # packages, the desk application).
        _device_state(self, "pi", packages=_packages_status(updates=5, security=2))
        _application(self, "desk", device_id="pi", version="3.4.1")
        # spare: clean, and a thin host (os + packages only).
        _device_state(self, "spare", os_name="Debian", os_version="12",
                      kernel="", architecture="",
                      packages=_packages_status(updates=0, security=0))
        self.service.tick(now=NOW)

    def _project(self, slug):
        self.db.execute(
            "INSERT INTO projects(project_id,slug,name,created_at,updated_at)"
            " VALUES(?,?,?,?,?)",
            (0, slug, slug.title(), NOW.isoformat(), NOW.isoformat()))

    def test_list_filters(self):
        self.assertEqual(len(self.service.list()), 7)  # pi: 5, spare: 2
        self.assertEqual(len(self.service.list(device="pi")), 5)
        self.assertEqual(len(self.service.list(device="spare")), 2)
        self.assertEqual(len(self.service.list(kind="runtime")), 0)
        self.assertEqual(len(self.service.list(kind="os")), 2)
        self.assertEqual([c["name"] for c in self.service.list(name="desk")], ["Desk"])
        self.assertEqual([c["application"] for c in self.service.list(application="desk")], ["desk"])
        self.assertEqual(len(self.service.list(state="security_update")), 1)
        with self.assertRaises(SoftwareError):
            self.service.list(kind="bogus")
        with self.assertRaises(SoftwareError):
            self.service.list(state="bogus")

    def test_project_filter(self):
        # Assign both devices to the project through membership.
        for device_id in ("pi", "spare"):
            self.db.execute(
                "INSERT INTO project_members(project_id,kind,object_id,added_at)"
                " VALUES(0,'device',?,?)", (device_id, NOW.isoformat()))
        self.assertEqual(len(self.service.list(project="proj")), 7)
        self.assertEqual(self.service.list(project="ghost"), [])

    def test_device_software(self):
        posture = self.service.device_software("pi")
        self.assertEqual(posture["state"], "security_update")
        self.assertEqual(posture["component_count"], 5)
        self.assertEqual(posture["state_counts"]["security_update"], 1)
        self.assertIsNone(self.service.device_software("nope"))

    def test_updates_split(self):
        result = self.service.updates()
        self.assertEqual(result["security_count"], 1)
        self.assertEqual(result["available_count"], 0)
        self.assertEqual(result["security"][0]["device_id"], "pi")
        # ... and once pi's counts clear, it moves to the available queue.
        _device_state(self, "pi", packages=_packages_status(updates=5, security=0),
                      last_seen=(NOW + timedelta(hours=1)).isoformat())
        self.service.tick(now=NOW + timedelta(hours=1))
        result = self.service.updates()
        self.assertEqual(result["security_count"], 0)
        self.assertEqual(result["available_count"], 1)
        self.assertEqual(result["available"][0]["device_id"], "pi")

    def test_export_honors_filters(self):
        payload = self.service.export()
        self.assertEqual(len(payload["rows"]), 7)
        self.assertEqual(payload["columns"][0], "device")
        filtered = self.service.export(device="pi", kind="package")
        self.assertEqual(len(filtered["rows"]), 1)
        self.assertEqual(filtered["rows"][0]["state"], "security_update")


# -- web surface -------------------------------------------------------------

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
        self.service = self.app.extensions["pinoc_software"]
        self.db.execute(
            "INSERT INTO projects(project_id,slug,name,created_at,updated_at)"
            " VALUES(1,'display','Display',?,?)", (NOW.isoformat(), NOW.isoformat()))

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

    def _seed(self):
        integrations = {"packages": {
            "name": "packages", "available": True, "health": "warning",
            "last_success": NOW.isoformat(), "last_attempt": NOW.isoformat(),
            "data_source": "apt-get", "error": None,
            "data": {"updates_available": 4, "security_updates": 1,
                     "reboot_required": False, "last_metadata_refresh": None},
            "critical": False}}
        self.state.publish([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi", online=True,
                        health="healthy", os="Raspbian", os_version="12",
                        kernel="6.6.31-v8", architecture="aarch64",
                        runtimes=[{"name": "python3", "version": "3.12.4"}],
                        last_seen=NOW.isoformat(),
                        last_successful_collection=NOW.isoformat(),
                        integrations=integrations)
        ], replace=True)
        self.service.tick(now=NOW)

    def test_app_builds_and_exposes_service(self):
        self.assertIsNotNone(self.service)
        self._login("bob")
        self.assertEqual(self.client.get("/software").status_code, 200)

    def test_unauthenticated_api_is_401(self):
        for path in ("/api/v1/software", "/api/v1/devices/pi/software",
                     "/api/v1/software/updates", "/api/v1/software/export"):
            self.assertEqual(self.client.get(path).status_code, 401, msg=path)

    def test_viewer_reads(self):
        self._seed()
        self._login("alice")
        for path in ("/api/v1/software", "/api/v1/devices/pi/software",
                     "/api/v1/software/updates", "/api/v1/software/export",
                     "/api/v1/software/export?format=csv"):
            self.assertEqual(self.client.get(path).status_code, 200, msg=path)

    def test_token_scope_permissions_registered(self):
        permissions = self.app.config["TOKEN_SCOPE_PERMISSIONS"]
        for endpoint in ("api_v1_software", "api_v1_device_software",
                         "api_v1_software_updates", "api_v1_software_export"):
            self.assertEqual(permissions[endpoint], "view", msg=endpoint)

    def test_list_endpoint_with_filters(self):
        self._seed()
        self._login("bob")
        body = self.client.get("/api/v1/software").get_json()
        self.assertEqual(len(body["components"]), 5)  # os, kernel, arch, python3, packages
        self.assertEqual(len(self.client.get(
            "/api/v1/software?kind=runtime").get_json()["components"]), 1)
        self.assertEqual(self.client.get(
            "/api/v1/software?state=security_update").get_json()["components"][0]["name"], "packages")
        self.assertEqual(self.client.get(
            "/api/v1/software?kind=bogus").status_code, 400)

    def test_device_software_endpoint(self):
        self._seed()
        self._login("bob")
        body = self.client.get("/api/v1/devices/pi/software").get_json()
        self.assertEqual(body["state"], "security_update")
        self.assertEqual(len(body["components"]), 5)
        self.assertEqual(self.client.get("/api/v1/devices/nope/software").status_code, 404)

    def test_updates_endpoint(self):
        self._seed()
        self._login("bob")
        body = self.client.get("/api/v1/software/updates").get_json()
        self.assertEqual(body["security_count"], 1)
        self.assertEqual(body["available_count"], 0)

    def test_export_json_and_csv(self):
        self._seed()
        self._login("bob")
        json_response = self.client.get("/api/v1/software/export?format=json")
        self.assertEqual(json_response.status_code, 200)
        self.assertEqual(len(json_response.get_json()["rows"]), 5)
        self.assertIn("generated_at", json_response.get_json())
        csv_response = self.client.get("/api/v1/software/export?format=csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response.mimetype, "text/csv")
        text = csv_response.get_data(as_text=True)
        self.assertIn("component,kind", text.splitlines()[0])
        self.assertIn("Raspbian 12", text)
        self.assertEqual(self.client.get(
            "/api/v1/software/export?format=xml").status_code, 400)

    def test_credentials_are_redacted(self):
        self._login("bob")
        self.db.execute(
            "INSERT INTO software_components(device_id,name,kind,version,"
            "source,confidence,state,state_reasons_json,created_at,updated_at)"
            " VALUES('pi','tokenizer','runtime','9.9 token=supersecretvalue','device_state',"
            "1.0,'current','[]',?,?)", (NOW.isoformat(), NOW.isoformat()))
        text = self.client.get("/api/v1/software?kind=runtime").get_data(as_text=True)
        self.assertNotIn("supersecretvalue", text)

    def test_no_history_service_is_503(self):
        # Without a history database the service is absent; the endpoints
        # report unavailability rather than failing the process. There is no
        # security layer either (no database for the users table), so an
        # unauthenticated request must reach the 503 branch directly.
        app = create_app(PiNOCState(),
                         {"TESTING": True, "AUTH_ENABLED": True,
                          "SECRET_KEY": "test-secret"}, None, None)
        self.assertIsNone(app.extensions["pinoc_software"])
        client = app.test_client()
        for path in ("/api/v1/software", "/api/v1/software/updates"):
            self.assertEqual(client.get(path).status_code, 503, msg=path)
        actions = app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()


# -- configuration validation -----------------------------------------------

class TestConfigValidation(unittest.TestCase):
    def test_valid_section_accepted(self):
        validate_software({"software": {
            "enabled": False, "refresh_seconds": 60, "stale_seconds": 300,
            "runtimes_check_seconds": 3600}})

    def test_absent_section_is_valid(self):
        validate_software({})
        validate_software({"software": None})

    def test_invalid_values_rejected(self):
        cases = [
            {"software": "on"},
            {"software": {"enabled": "yes"}},
            {"software": {"refresh_seconds": 29}},
            {"software": {"refresh_seconds": 86401}},
            {"software": {"refresh_seconds": "fast"}},
            {"software": {"refresh_seconds": True}},
            {"software": {"stale_seconds": 59}},
            {"software": {"stale_seconds": 2592001}},
            {"software": {"runtimes_check_seconds": 59}},
            {"software": {"runtimes_check_seconds": 86401}},
            {"software": {"runtimes_check_seconds": "x"}},
        ]
        for value in cases:
            with self.assertRaises(ValueError, msg=value):
                validate_software(value)

    def test_validate_config_runs_software(self):
        base = {"devices": [], "polling": {"fleet_seconds": 10}}
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            self.assertEqual(validate_config(
                {**base, "software": {"stale_seconds": 300}}, Path(tmp)),
                {**base, "software": {"stale_seconds": 300}})
            with self.assertRaises(ValueError):
                validate_config(
                    {**base, "software": {"stale_seconds": 5}}, Path(tmp))


# -- no-database degradation -------------------------------------------------

class TestNoDatabase(unittest.TestCase):
    def setUp(self):
        self.service = SoftwareService(None, state=PiNOCState(),
                                       config=DEFAULT_SOFTWARE_CONFIG)

    def test_list_is_empty(self):
        self.assertEqual(self.service.list(), [])

    def test_device_software_is_none(self):
        self.assertIsNone(self.service.device_software("pi"))

    def test_updates_is_empty(self):
        result = self.service.updates()
        self.assertEqual(result["security"], [])
        self.assertEqual(result["available"], [])

    def test_export_is_empty(self):
        payload = self.service.export()
        self.assertEqual(payload["rows"], [])

    def test_posture_is_unknown(self):
        self.assertEqual(self.service.posture()["state"], "unknown")

    def test_tick_reports_unavailable(self):
        self.assertEqual(self.service.tick(now=NOW)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
