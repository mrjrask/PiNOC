"""Coverage for the project model (PiNOC 2.0 Phase 1, P1-R01).

Three layers, the same shape as the other Phase 1 model tests:

* :class:`EnvstatesTest` -- the canonical health-state contract in
  ``pinoc/envstates.py`` (severity order, criticality escalation policy,
  rollups, freshness math). Pure functions; no I/O.
* :class:`ProjectServiceTest` -- the registry service against a real
  SQLite database: CRUD, slugs, lifecycle rules, archived read-only
  behavior, audited membership, per-criticality health rollups,
  unassigned inventory, the drill-down graph, and the no-database
  degradation path.
* :class:`ProjectsWebTest` -- the HTTP surface through ``create_app()``:
  auth gating (401 unauthenticated, 403 viewer writes, admin CRUD),
  the lifecycle and membership endpoints, and the /projects page.
"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from pinoc.database import Database
from pinoc.envstates import (
    CRITICALITIES,
    HEALTH_STATES,
    escalate,
    fresh_state,
    is_stale,
    normalize_state,
    rank_of,
    rollup,
    worst,
)
from pinoc.history import HistoryManager
from pinoc.models import DeviceState
from pinoc.projects import (
    LIFECYCLES,
    MEMBER_KINDS,
    ProjectError,
    ProjectService,
    slugify,
)
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

UTC = timezone.utc
NOW = datetime.now(UTC)


def make_state(devices):
    state = PiNOCState()
    state.publish(devices, replace=True)
    return state


class EnvstatesTest(unittest.TestCase):
    def test_eight_canonical_states_in_severity_order(self):
        self.assertEqual(HEALTH_STATES,
                         ("healthy", "maintenance", "unknown", "stale",
                          "warning", "degraded", "offline", "critical"))
        self.assertEqual(rank_of("healthy"), 0)
        self.assertEqual(rank_of("critical"), len(HEALTH_STATES) - 1)

    def test_normalize_maps_foreign_vocabulary_to_unknown(self):
        self.assertEqual(normalize_state("Healthy"), "healthy")
        self.assertEqual(normalize_state("unavailable"), "unknown")
        self.assertEqual(normalize_state(None), "unknown")
        self.assertEqual(normalize_state(""), "unknown")

    def test_worst_picks_most_severe(self):
        self.assertEqual(worst("healthy", "stale", "healthy"), "stale")
        self.assertEqual(worst("healthy"), "healthy")
        self.assertEqual(worst(), "unknown")
        self.assertEqual(worst("offline", "warning"), "offline")

    def test_criticality_escalation_policy(self):
        # A "critical" project escalates warnings to degraded and staleness
        # to critical; lower criticalities do less of the same.
        self.assertEqual(escalate("stale", "low"), "stale")
        self.assertEqual(escalate("stale", "standard"), "warning")
        self.assertEqual(escalate("stale", "high"), "degraded")
        self.assertEqual(escalate("stale", "critical"), "critical")
        self.assertEqual(escalate("warning", "critical"), "degraded")
        self.assertEqual(escalate("warning", "low"), "warning")
        # Healthy and maintenance never escalate: planned downtime is a
        # state, not a problem, and must not count against a rollup.
        self.assertEqual(escalate("healthy", "critical"), "healthy")
        self.assertEqual(escalate("maintenance", "critical"), "maintenance")

    def test_rollup_healthy_members(self):
        state, reasons = rollup([("pi", "device", "healthy")], "critical")
        self.assertEqual(state, "healthy")
        self.assertEqual(reasons, [])

    def test_rollup_escalates_and_names_contributors(self):
        state, reasons = rollup(
            [("pi", "device", "stale"), ("other", "device", "healthy")], "standard")
        self.assertEqual(state, "warning")
        self.assertEqual(reasons, ["device.warning:pi"])

    def test_rollup_excludes_maintenance(self):
        state, reasons = rollup([("pi", "device", "maintenance")], "critical")
        self.assertEqual(state, "healthy")
        self.assertEqual(reasons, [])

    def test_rollup_empty_is_healthy(self):
        self.assertEqual(rollup([], "standard"), ("healthy", []))

    def test_freshness_math(self):
        # A *missing* observation is stale (there was never a success).
        self.assertTrue(is_stale(None, 3600, NOW))
        self.assertFalse(is_stale(NOW.isoformat(), 3600, NOW))
        self.assertTrue(is_stale((NOW - timedelta(hours=2)).isoformat(), 3600, NOW))
        self.assertEqual(fresh_state(None, 3600, NOW), "unknown")
        self.assertEqual(fresh_state(NOW.isoformat(), 3600, NOW), "healthy")
        self.assertEqual(fresh_state((NOW - timedelta(hours=2)).isoformat(), 3600, NOW), "stale")


class ProjectServiceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.audit = []
        self.service = ProjectService(self.db, state=None, audit=self._record_audit)

    def tearDown(self):
        self._tmp.cleanup()

    def _record_audit(self, user, role, ip, device, action, target,
                       params, auth, result=None, exit_code=None,
                       duration=None, error=None):
        self.audit.append({"user": user, "action": action, "target": target,
                           "params": params, "result": result})

    def _audit_actions(self):
        return [entry["action"] for entry in self.audit]

    def _device_row(self, device_id, hostname=None):
        self.db.execute(
            "INSERT INTO devices(device_id,hostname,friendly_name,created_at,updated_at) "
            "VALUES(?,?,?,?,?)",
            (device_id, hostname or device_id, device_id.title(),
             NOW.isoformat(), NOW.isoformat()))

    # -- slugs and CRUD ------------------------------------------------------
    def test_slugify(self):
        self.assertEqual(slugify("Desk Display"), "desk-display")
        self.assertEqual(slugify("Magic Mirror 2.0"), "magic-mirror-2-0")
        self.assertEqual(slugify("!!!"), "project")

    def test_create_defaults_and_round_trip(self):
        project = self.service.create({"name": "Desk Display"})
        self.assertEqual(project["id"], "desk-display")
        self.assertEqual(project["lifecycle"], "planned")
        self.assertEqual(project["criticality"], "standard")
        self.assertEqual(project["tags"], [])
        self.assertEqual(project["links"], [])
        self.assertIsNone(project["owner"])
        self.assertFalse(project["archived"])
        self.assertEqual(project["member_counts"], {})
        # Both the slug and the integer id address the same row.
        self.assertEqual(self.service.get("desk-display")["name"], "Desk Display")
        self.assertEqual(self.service.get(project["project_id"])["id"], "desk-display")

    def test_create_duplicate_slug_rejected(self):
        self.service.create({"name": "Desk Display"})
        with self.assertRaises(ProjectError):
            self.service.create({"name": "Desk Display"})  # same derived slug
        with self.assertRaises(ProjectError):
            self.service.create({"name": "Other", "slug": "desk-display"})

    def test_create_rejects_invalid_input(self):
        for payload in ({}, {"name": ""}, {"name": "x" * 201},
                        {"name": "Ok", "slug": "Bad Slug"},
                        {"name": "Ok", "lifecycle": "archived"},
                        {"name": "Ok", "lifecycle": "exploded"},
                        {"name": "Ok", "criticality": "apocalyptic"}):
            with self.assertRaises(ProjectError):
                self.service.create(payload)

    def test_create_stores_metadata(self):
        project = self.service.create({
            "name": "ADS-B", "description": "Airband ground station",
            "lifecycle": "active", "criticality": "high", "owner": "jason",
            "tags": ["aviation", "display"], "notes": "keep the antenna clear",
            "links": [{"label": "docs", "url": "https://example.com/docs"}],
        })
        self.assertEqual(project["lifecycle"], "active")
        self.assertEqual(project["criticality"], "high")
        self.assertEqual(project["tags"], ["aviation", "display"])
        self.assertEqual(project["links"], [{"label": "docs", "url": "https://example.com/docs"}])
        self.assertEqual(project["owner"], "jason")
        self.assertIn("project.create", self._audit_actions())
        # Non-http(s) links and non-list tags are rejected.
        with self.assertRaises(ProjectError):
            self.service.create({"name": "Bad Link", "links": ["ftp://example.com/x"]})
        with self.assertRaises(ProjectError):
            self.service.create({"name": "Bad Tags", "tags": 42})

    def test_update_fields_and_audits(self):
        self.service.create({"name": "Desk Display"})
        project = self.service.update("desk-display", {
            "name": "Desk Display v2", "description": "new description",
            "owner": "jason", "tags": ["kiosk"],
            "criticality": "critical", "lifecycle": "active",
        })
        self.assertEqual(project["name"], "Desk Display v2")
        self.assertEqual(project["owner"], "jason")
        self.assertEqual(project["tags"], ["kiosk"])
        self.assertEqual(project["criticality"], "critical")
        self.assertEqual(project["lifecycle"], "active")
        for action in ("project.update", "project.criticality", "project.lifecycle"):
            self.assertIn(action, self._audit_actions())
        self.assertEqual(self.service.get("desk-display")["owner"], "jason")

    def test_update_unknown_project(self):
        with self.assertRaises(ProjectError):
            self.service.update("ghost", {"name": "x"})

    def test_lifecycle_cannot_be_set_to_archived_via_update(self):
        self.service.create({"name": "Desk"})
        with self.assertRaises(ProjectError):
            self.service.update("desk", {"lifecycle": "archived"})

    # -- lifecycle: archive / restore -----------------------------------------
    def test_archive_makes_project_read_only(self):
        self._device_row("pi")
        self.service.create({"name": "Desk"})
        archived = self.service.archive("desk", actor="bob", reason="retiring the hardware")
        self.assertEqual(archived["lifecycle"], "archived")
        self.assertTrue(archived["archived"])
        self.assertIsNotNone(archived["archived_at"])
        self.assertEqual(archived["archived_reason"], "retiring the hardware")
        for write in (lambda: self.service.update("desk", {"name": "nope"}),
                      lambda: self.service.add_members("desk", "device", ["pi"]),
                      lambda: self.service.remove_members("desk", "device", ["pi"])):
            with self.assertRaises(ProjectError) as ctx:
                write()
            self.assertIn("read-only", str(ctx.exception))
        # Archiving is idempotent: no second audit entry, same row.
        before = len(self.audit)
        self.assertEqual(self.service.archive("desk")["lifecycle"], "archived")
        self.assertEqual(len(self.audit), before)
        self.assertIn("project.archive", self._audit_actions())

    def test_restore_round_trip(self):
        self.service.create({"name": "Desk"})
        with self.assertRaises(ProjectError):
            self.service.restore("desk")  # only archived projects can be restored
        self.service.archive("desk")
        restored = self.service.restore("desk", actor="bob")
        self.assertEqual(restored["lifecycle"], "retired")
        self.assertIsNone(restored["archived_at"])
        self.assertIsNone(restored["archived_reason"])
        self.assertIn("project.restore", self._audit_actions())

    def test_list_filters_archived_and_lifecycle(self):
        self.service.create({"name": "Alpha", "lifecycle": "active"})
        self.service.create({"name": "Beta", "lifecycle": "planned"})
        self.service.archive("alpha")
        self.assertEqual([p["id"] for p in self.service.list_projects()], ["beta"])
        self.assertEqual({p["id"] for p in self.service.list_projects(include_archived=True)},
                         {"alpha", "beta"})
        self.assertEqual([p["id"] for p in self.service.list_projects(lifecycle="planned")],
                         ["beta"])
        with self.assertRaises(ProjectError):
            self.service.list_projects(lifecycle="bogus")

    # -- membership -------------------------------------------------------------
    def test_membership_add_remove_resurrect(self):
        self._device_row("pi")
        self.service.create({"name": "Desk"})
        added = self.service.add_members("desk", "device", ["pi"])
        self.assertEqual(added["added"], ["pi"])
        # Re-adding a current member is a no-op (no duplicate rows, no audit).
        before = len(self.audit)
        self.assertEqual(self.service.add_members("desk", "device", ["pi"])["added"], [])
        self.assertEqual(len(self.audit), before)
        self.assertEqual(self.service.members("desk"), {"device": ["pi"]})
        self.assertEqual(self.service.member_counts("desk"), {"device": 1})
        removed = self.service.remove_members("desk", "device", ["pi"])
        self.assertEqual(removed["removed"], ["pi"])
        self.assertNotIn("device", self.service.members("desk"))
        # The soft-removed row is resurrected instead of duplicated.
        self.assertEqual(self.service.add_members("desk", "device", ["pi"])["added"], ["pi"])
        self.assertEqual(self.service.members("desk")["device"].count("pi"), 1)

    def test_membership_validates_devices_against_roster(self):
        self._device_row("pi")
        self.service.create({"name": "Desk"})
        with self.assertRaises(ProjectError) as ctx:
            self.service.add_members("desk", "device", ["ghost"])
        self.assertIn("ghost", str(ctx.exception))

    def test_membership_rejects_bad_kind_or_ids(self):
        self.service.create({"name": "Desk"})
        with self.assertRaises(ProjectError):
            self.service.add_members("desk", "widget", ["x"])
        with self.assertRaises(ProjectError):
            self.service.add_members("desk", "device", ["bad id!"])
        with self.assertRaises(ProjectError):
            self.service.add_members("desk", "device", [])
        with self.assertRaises(ProjectError):
            self.service.add_members("desk", "device", ["d%d" % i for i in range(201)])

    def test_membership_audits(self):
        self._device_row("pi")
        self._device_row("pi2")
        self.service.create({"name": "Desk"})
        self.service.add_members("desk", "device", ["pi", "pi2"])
        self.service.remove_members("desk", "device", ["pi"], actor="bob")
        self.assertIn("project.members.add", self._audit_actions())
        self.assertIn("project.members.remove", self._audit_actions())
        add = [entry for entry in self.audit if entry["action"] == "project.members.add"][0]
        self.assertEqual(add["user"], "system")
        self.assertEqual(add["target"], "desk")
        self.assertEqual(add["params"]["kind"], "device")
        self.assertEqual(add["params"]["added"], ["pi", "pi2"])
        remove = [entry for entry in self.audit if entry["action"] == "project.members.remove"][0]
        self.assertEqual(remove["user"], "bob")
        self.assertEqual(remove["params"]["removed"], ["pi"])

    def test_non_device_kinds_take_opaque_ids(self):
        self.service.create({"name": "Desk"})
        added = self.service.add_members("desk", "application", ["magicmirror-1"])
        self.assertEqual(added["added"], ["magicmirror-1"])
        self.assertEqual(self.service.members("desk")["application"], ["magicmirror-1"])

    # -- unassigned inventory ----------------------------------------------------
    def test_unassigned_counts_only_active_projects(self):
        self._device_row("pi")
        self._device_row("spare")
        self.service.create({"name": "Desk"})
        self.service.add_members("desk", "device", ["pi"])
        self.service.create({"name": "Vault"})
        self.service.add_members("vault", "device", ["spare"])
        self.service.archive("vault")
        result = self.service.unassigned("device")
        self.assertEqual(result["assigned"], ["pi"])
        self.assertEqual(result["unassigned"], ["spare"])  # its only home was archived
        self.service.add_members("desk", "device", ["spare"])
        self.assertEqual(self.service.unassigned("device")["unassigned"], [])

    def test_unassigned_rejects_bad_kind(self):
        with self.assertRaises(ProjectError):
            self.service.unassigned("widget")

    def test_unassigned_kind_without_roster_is_empty(self):
        # Kinds whose Phase 1 model does not exist in this checkout have no
        # registered roster source: the view is empty, never an error.
        self.service.create({"name": "Desk"})
        self.assertEqual(self.service.unassigned("feed"),
                         {"kind": "feed", "assigned": [], "unassigned": []})

    # -- health rollup ----------------------------------------------------------
    def _service_with_state(self, devices):
        return ProjectService(self.db, state=make_state(devices), audit=self._record_audit)

    def _one_device_project(self, service, criticality, device_id="pi"):
        # A distinct slug per criticality: the loop reuses one database.
        slug = f"desk-{criticality}"
        self.service.create({"name": "Desk", "slug": slug, "criticality": criticality})
        service.add_members(slug, "device", [device_id])
        return slug

    def test_health_rollup_scales_with_criticality(self):
        stale_device = DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                                   online=True, health="healthy", stale=True)
        for criticality, expected in (("low", "stale"), ("standard", "warning"),
                                      ("high", "degraded"), ("critical", "critical")):
            service = self._service_with_state([stale_device])
            slug = self._one_device_project(service, criticality)
            health = service.health(slug)
            self.assertEqual(health["health"], expected, f"criticality={criticality}")
            self.assertTrue(health["reasons"])

    def test_health_offline_device_offline_in_every_criticality(self):
        device = DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                             online=False, health="offline")
        for criticality in CRITICALITIES:
            service = self._service_with_state([device])
            slug = self._one_device_project(service, criticality)
            self.assertEqual(service.health(slug)["health"], "offline")

    def test_health_healthy_project(self):
        device = DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                             online=True, health="healthy")
        service = self._service_with_state([device])
        slug = self._one_device_project(service, "low")
        health = service.health(slug)
        self.assertEqual(health["health"], "healthy")
        self.assertEqual(health["reasons"], [])
        self.assertEqual(health["active_alerts"], [])
        self.assertEqual(health["members"]["device"][0]["health"], "healthy")

    def test_health_unregistered_kind_reads_unknown(self):
        # "application" has no registered health source until P1-R02: it
        # counts as an unknown member (for the rollup) rather than an error.
        service = self._service_with_state([])
        self.service.create({"name": "Desk"})
        service.add_members("desk", "application", ["app-x"])
        health = service.health("desk")
        self.assertEqual(health["health"], "unknown")
        self.assertEqual(health["members"]["application"][0]["health"], "unknown")

    def test_health_missing_device_reads_unknown(self):
        service = self._service_with_state([])
        self.service.create({"name": "Desk"})
        service.add_members("desk", "device", ["ghost"])  # roster is empty: unverifiable
        health = service.health("desk")
        self.assertEqual(health["health"], "unknown")
        entry = health["members"]["device"][0]
        self.assertEqual(entry["health"], "unknown")
        self.assertIn("not in roster", entry["reasons"][0])

    def test_health_archived_and_retired(self):
        service = self._service_with_state([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                        online=True, health="healthy")])
        self.service.create({"name": "Desk"})
        service.add_members("desk", "device", ["pi"])
        self.service.archive("desk")
        health = service.health("desk")
        self.assertEqual(health["health"], "maintenance")
        self.assertEqual(health["reasons"], ["archived project (read-only)"])
        self.service.restore("desk")  # -> retired
        self.assertEqual(service.health("desk")["health"], "maintenance")

    def test_health_includes_only_active_alerts(self):
        device = DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                             online=True, health="critical")
        service = self._service_with_state([device])
        self.service.create({"name": "Desk"})
        service.add_members("desk", "device", ["pi"])
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,"
            "last_seen_at,state) VALUES(?,?,?,?,?,?,?,?)",
            ("pi", "disk_space", "critical", "disk full", "pi:disk_space:/",
             NOW.isoformat(), NOW.isoformat(), "active"))
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,"
            "last_seen_at,resolved_at,state) VALUES(?,?,?,?,?,?,?,?,?)",
            ("pi", "reboot", "warning", "was rebooted", "pi:reboot:",
             NOW.isoformat(), NOW.isoformat(), NOW.isoformat(), "resolved"))
        health = service.health("desk")
        self.assertEqual(health["health"], "critical")
        self.assertEqual(len(health["active_alerts"]), 1)  # the resolved one is excluded
        self.assertEqual(health["active_alerts"][0]["alert_type"], "disk_space")

    def test_project_summaries_excludes_archived(self):
        service = self._service_with_state([])
        self.service.create({"name": "Alpha"})
        self.service.create({"name": "Beta"})
        self.service.archive("alpha")
        summaries = service.project_summaries()
        self.assertEqual([s["id"] for s in summaries], ["beta"])

    # -- graph and card list ------------------------------------------------------
    def test_graph_enriches_devices(self):
        device = DeviceState(
            id="pi", hostname="pi", friendly_name="Pi", online=True, health="healthy",
            services=[{"name": "nginx", "active": True}, {"name": "sshd", "active": True}],
            integrations={"raid": {"health": "healthy"}})
        service = self._service_with_state([device])
        self.service.create({"name": "Desk"})
        service.add_members("desk", "device", ["pi"])
        graph = service.graph("desk")
        self.assertEqual(graph["project"]["id"], "desk")
        self.assertEqual(graph["project"]["name"], "Desk")
        self.assertEqual(graph["health"]["health"], "healthy")
        member = graph["members"]["device"][0]
        self.assertEqual(member["object_id"], "pi")
        self.assertTrue(member["online"])
        self.assertEqual(member["services"], ["nginx", "sshd"])
        self.assertEqual(member["integrations"], ["raid"])

    def test_graph_unknown_project_raises(self):
        with self.assertRaises(ProjectError):
            self.service.graph("ghost")

    def test_list_includes_rollup_for_cards(self):
        service = self._service_with_state([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                        online=True, health="healthy", stale=True)])
        self.service.create({"name": "Desk", "criticality": "standard"})
        service.add_members("desk", "device", ["pi"])
        # The *stateful* service rolls up from the live device cache...
        listed = service.list_projects()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["member_counts"], {"device": 1})
        self.assertEqual(listed[0]["health"], "warning")  # standard escalates stale
        self.assertEqual(listed[0]["active_alert_count"], 0)
        # ...and the stateless twin reads the same registry with an unknown
        # device health rather than failing the grid.
        self.assertEqual(self.service.list_projects()[0]["health"], "unknown")

    # -- no-database degradation ----------------------------------------------------
    def test_no_database_degrades_to_empty(self):
        service = ProjectService(None)
        self.assertEqual(service.list_projects(), [])
        self.assertIsNone(service.get("desk"))
        self.assertEqual(service.project_summaries(), [])
        with self.assertRaises(ProjectError):
            service.create({"name": "Desk"})
        with self.assertRaises(ProjectError):
            service.archive("desk")
        self.assertEqual(service.unassigned("device"),
                         {"kind": "device", "unassigned": [], "assigned": []})


class ProjectsWebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(f"{self._tmp.name}/db.sqlite")
        assert self.db.initialize()
        self.history = HistoryManager(self.db, {})
        self.state = PiNOCState()
        self.state.publish([
            DeviceState(id="pi", hostname="pi", friendly_name="Pi",
                        online=True, health="healthy"),
        ], replace=True)
        self.app = create_app(
            self.state, {"TESTING": True, "AUTH_ENABLED": True,
                         "SECRET_KEY": "test-secret", "DATABASE": self.db},
            self.history, None)
        self.security = self.app.extensions["pinoc_security"]
        self.security.create_user("alice", "pw1234567890", "viewer")
        self.security.create_user("bob", "pw1234567890", "administrator")
        self.client = self.app.test_client()

    def tearDown(self):
        actions = self.app.extensions.get("pinoc_actions")
        if actions:
            actions.stop()
        self._tmp.cleanup()

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
        return self.client.post(path, json=body or {}, headers={"X-CSRF-Token": self._csrf()})

    def _patch(self, path, body=None):
        return self.client.patch(path, json=body or {}, headers={"X-CSRF-Token": self._csrf()})

    def _delete(self, path, body=None):
        return self.client.delete(path, json=body, headers={"X-CSRF-Token": self._csrf()})

    def _create_project(self, name="Desk Display", **extra):
        response = self._post("/api/v1/projects", {"name": name, **extra})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()["project"]

    # -- auth gating -------------------------------------------------------
    def test_unauthenticated_api_and_page(self):
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/projects/desk-display").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/projects/desk-display/health").status_code, 401)
        self.assertEqual(self.client.get("/projects").status_code, 302)  # -> login

    def test_viewer_reads_but_cannot_write(self):
        self._login("alice")
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 200)
        self.assertEqual(self._post("/api/v1/projects", {"name": "Desk"}).status_code, 403)

    def test_token_scope_permissions_registered(self):
        permissions = self.app.config["TOKEN_SCOPE_PERMISSIONS"]
        for endpoint, permission in {
            "api_v1_projects": "view",
            "api_v1_projects_create": "config.write",
            "api_v1_project": "view",
            "api_v1_project_update": "config.write",
            "api_v1_project_archive": "config.write",
            "api_v1_project_restore": "config.write",
            "api_v1_project_health": "view",
            "api_v1_project_graph": "view",
            "api_v1_project_members_add": "config.write",
            "api_v1_project_members_remove": "config.write",
            "api_v1_projects_unassigned": "view",
        }.items():
            self.assertEqual(permissions[endpoint], permission)

    # -- CRUD round trip -----------------------------------------------------
    def test_admin_create_get_update(self):
        self._login("bob")
        project = self._create_project("Desk Display", lifecycle="active",
                                       criticality="high", tags=["kiosk"],
                                       links=[{"label": "docs", "url": "https://example.com"}])
        self.assertEqual(project["id"], "desk-display")
        self.assertEqual(project["tags"], ["kiosk"])

        detail = self.client.get("/api/v1/projects/desk-display")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["project"]["lifecycle"], "active")

        updated = self._patch("/api/v1/projects/desk-display", {"description": "new"})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["project"]["description"], "new")

        self.assertEqual(self.client.get("/api/v1/projects/nope").status_code, 404)

    def test_admin_cannot_bypass_validation(self):
        self._login("bob")
        self.assertEqual(self._post("/api/v1/projects", {}).status_code, 400)
        self._create_project("Desk Display")
        self.assertEqual(self._post("/api/v1/projects", {"name": "Desk Display"}).status_code, 409)
        self.assertEqual(
            self._post("/api/v1/projects", {"name": "X", "lifecycle": "archived"}).status_code, 400)

    def test_list_shows_rollup_and_counts(self):
        self._login("bob")
        project = self._create_project("Desk Display")
        self._post(f"/api/v1/projects/{project['id']}/members",
                   {"kind": "device", "object_ids": ["pi"]})
        response = self.client.get("/api/v1/projects")
        self.assertEqual(response.status_code, 200)
        cards = response.get_json()["projects"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["member_counts"], {"device": 1})
        self.assertEqual(cards[0]["health"], "healthy")

    # -- lifecycle --------------------------------------------------------------
    def test_archive_read_only_restore(self):
        self._login("bob")
        project = self._create_project("Desk Display")
        archived = self._post(f"/api/v1/projects/{project['id']}/archive",
                              {"reason": "hardware retires"})
        self.assertEqual(archived.status_code, 200)
        self.assertEqual(archived.get_json()["project"]["lifecycle"], "archived")
        # Archived projects are read-only: writes get 409.
        self.assertEqual(
            self._patch(f"/api/v1/projects/{project['id']}", {"name": "nope"}).status_code, 409)
        self.assertEqual(
            self._post(f"/api/v1/projects/{project['id']}/members",
                       {"kind": "device", "object_ids": ["pi"]}).status_code, 409)
        # Restore brings the project back as retired; repeating it is a 409.
        self.assertEqual(
            self._post(f"/api/v1/projects/{project['id']}/restore", {}).status_code, 200)
        self.assertEqual(
            self.client.get(f"/api/v1/projects/{project['id']}").get_json()["project"]["lifecycle"],
            "retired")
        self.assertEqual(
            self._post(f"/api/v1/projects/{project['id']}/restore", {}).status_code, 409)

    # -- membership ---------------------------------------------------------------
    def test_membership_add_remove(self):
        self._login("bob")
        project = self._create_project("Desk Display")
        added = self._post(f"/api/v1/projects/{project['id']}/members",
                           {"kind": "device", "object_ids": ["pi"]})
        self.assertEqual(added.status_code, 201)
        self.assertEqual(added.get_json()["added"], ["pi"])
        detail = self.client.get(f"/api/v1/projects/{project['id']}")
        self.assertEqual(detail.get_json()["project"]["members"]["device"], ["pi"])
        removed = self._delete(f"/api/v1/projects/{project['id']}/members",
                               {"kind": "device", "object_ids": ["pi"]})
        self.assertEqual(removed.get_json()["removed"], ["pi"])
        # The device roster comes from the state cache: unknown ids are 400.
        self.assertEqual(
            self._post(f"/api/v1/projects/{project['id']}/members",
                       {"kind": "device", "object_ids": ["ghost"]}).status_code, 400)

    # -- health / graph / unassigned ---------------------------------------------
    def test_health_endpoint(self):
        self._login("bob")
        project = self._create_project("Desk Display")
        self._post(f"/api/v1/projects/{project['id']}/members",
                   {"kind": "device", "object_ids": ["pi"]})
        # A critical alert on the device flips the state cache...
        self.state.set_alerts([
            {"device_id": "pi", "state": "active", "severity": "critical",
             "message": "disk full"}])
        # ...and the durable alerts table feeds the active-alerts strip.
        self.db.execute(
            "INSERT INTO alerts(device_id,alert_type,severity,message,fingerprint,opened_at,"
            "last_seen_at,state) VALUES(?,?,?,?,?,?,?,?)",
            ("pi", "disk_space", "critical", "disk full", "pi:disk_space:/",
             NOW.isoformat(), NOW.isoformat(), "active"))
        response = self.client.get(f"/api/v1/projects/{project['id']}/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["health"], "critical")
        self.assertTrue(payload["reasons"])
        self.assertEqual(len(payload["active_alerts"]), 1)

    def test_graph_endpoint(self):
        self._login("bob")
        project = self._create_project("Desk Display")
        self._post(f"/api/v1/projects/{project['id']}/members",
                   {"kind": "device", "object_ids": ["pi"]})
        response = self.client.get(f"/api/v1/projects/{project['id']}/graph")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["project"]["id"], project["id"])
        self.assertEqual(payload["members"]["device"][0]["object_id"], "pi")
        self.assertTrue(payload["members"]["device"][0]["online"])

    def test_unassigned_endpoint(self):
        self._login("bob")
        project = self._create_project("Desk Display")
        self._post(f"/api/v1/projects/{project['id']}/members",
                   {"kind": "device", "object_ids": ["pi"]})
        response = self.client.get("/api/v1/projects/unassigned?kind=device")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["assigned"], ["pi"])
        self.assertEqual(response.get_json()["unassigned"], [])

    # -- page --------------------------------------------------------------------
    def test_projects_page_renders(self):
        self._login("bob")
        page = self.client.get("/projects")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Projects", page.data)
        self.assertIn(b"project-detail", page.data)
        self.assertIn(b"PiNOC.projects()", page.data)


if __name__ == "__main__":
    unittest.main()
